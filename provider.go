package infoblox

import (
	"context"
	"fmt"
	ibclient "github.com/infobloxopen/infoblox-go-client/v2"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
	"strings"
)

// Provider facilitates DNS record manipulation with Infoblox
type Provider struct {
	Host     string `json:"host,omitempty"`
	Version  string `json:"version,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	View     string `json:"view,omitempty"`
	logger   *zap.Logger
}

// SetLogger sets the logger for the provider
func (p *Provider) SetLogger(logger *zap.Logger) {
	p.logger = logger
}

func (p *Provider) log() *zap.Logger {
	if p.logger == nil {
		return zap.NewNop()
	}
	return p.logger
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(_ context.Context, zone string) ([]libdns.Record, error) {
	p.log().Info("getting records", zap.String("zone", zone))
	conn, err := p.getConnector()
	if err != nil {
		p.log().Error("failed to get connector", zap.Error(err))
		return nil, fmt.Errorf("failed to get connector: %w", err)
	}
	qp := ibclient.NewQueryParams(false, map[string]string{"name": zone})

	var cnameRecords []ibclient.RecordCNAME
	err = conn.GetObject(&ibclient.RecordCNAME{}, "", qp, &cnameRecords)
	if err != nil {
		p.log().Error("failed to get CNAME records", zap.Error(err))
		return nil, fmt.Errorf("failed to get CNAME records: %w", err)
	}

	var txtRecords []ibclient.RecordTXT
	err = conn.GetObject(&ibclient.RecordTXT{}, "", qp, &txtRecords)
	if err != nil {
		p.log().Error("failed to get TXT records", zap.Error(err))
		return nil, fmt.Errorf("failed to get TXT records: %w", err)
	}

	var legitzone = strings.TrimSuffix(zone, ".")

	var list []libdns.Record
	for i := range cnameRecords {
		list = append(list, libdns.RR{
			Type: "CNAME",
			Name: strings.TrimSuffix(*cnameRecords[i].Name, "."+legitzone),
			Data: *cnameRecords[i].Canonical,
		})
	}

	for i := range txtRecords {
		list = append(list, libdns.RR{
			Type: "TXT",
			Name: strings.TrimSuffix(*txtRecords[i].Name, "."+legitzone),
			Data: *txtRecords[i].Text,
		})
	}

	p.log().Info("retrieved records", zap.String("zone", zone), zap.Int("count", len(list)))
	return list, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(_ context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.log().Info("appending records", zap.String("zone", zone), zap.Int("count", len(records)))
	var added []libdns.Record

	objMgr, err := p.getObjectManager()
	if err != nil {
		p.log().Error("failed to get object manager", zap.Error(err))
		return nil, fmt.Errorf("failed to get object manager: %w", err)
	}

	var legitzone = strings.TrimSuffix(zone, ".")

	for i := range records {
		var rec = records[i]
		var recRR = rec.RR()
		switch recRR.Type {
		case "CNAME":
			record, err := objMgr.CreateCNAMERecord(p.View, recRR.Data, recRR.Name+"."+legitzone, true, uint32(recRR.TTL.Seconds()), "", nil)
			if err != nil {
				p.log().Error("failed to create CNAME record", zap.String("name", recRR.Name), zap.Error(err))
				return added, fmt.Errorf("failed to create CNAME record %s: %w", recRR.Name, err)
			}
			added = append(added, libdns.RR{
				Type: "CNAME",
				Name: strings.TrimSuffix(*record.Name, "."+legitzone),
				Data: *record.Canonical,
			})
		case "TXT":
			record, err := objMgr.CreateTXTRecord(p.View, recRR.Name+"."+legitzone, recRR.Data, uint32(recRR.TTL.Seconds()), true, "", nil)
			if err != nil {
				p.log().Error("failed to create TXT record", zap.String("name", recRR.Name), zap.Error(err))
				return added, fmt.Errorf("failed to create TXT record %s: %w", recRR.Name, err)
			}
			added = append(added, libdns.RR{
				Type: "TXT",
				Name: strings.TrimSuffix(*record.Name, "."+legitzone),
				Data: *record.Text,
			})
		}
	}

	p.log().Info("appended records", zap.String("zone", zone), zap.Int("added", len(added)))
	return added, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(_ context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.log().Info("setting records", zap.String("zone", zone), zap.Int("count", len(records)))
	var updated []libdns.Record

	objMgr, err := p.getObjectManager()
	if err != nil {
		p.log().Error("failed to get object manager", zap.Error(err))
		return nil, fmt.Errorf("failed to get object manager: %w", err)
	}

	var legitzone = strings.TrimSuffix(zone, ".")

	for i := range records {
		var rec = records[i]
		var recRR = rec.RR()
		switch recRR.Type {
		case "CNAME":
			record, err := objMgr.GetCNAMERecord(p.View, "", recRR.Name)
			if err != nil {
				record, err = objMgr.CreateCNAMERecord(p.View, recRR.Data, recRR.Name+"."+legitzone, true, uint32(recRR.TTL.Seconds()), "", nil)
				if err != nil {
					p.log().Error("failed to create CNAME record", zap.String("name", recRR.Name), zap.Error(err))
					return updated, fmt.Errorf("failed to create CNAME record %s: %w", recRR.Name, err)
				}
			} else {
				_, err := objMgr.UpdateCNAMERecord(record.Ref, recRR.Data, *record.Name, *record.UseTtl, *record.Ttl, *record.Comment, record.Ea)
				if err != nil {
					p.log().Error("failed to update CNAME record", zap.String("name", recRR.Name), zap.Error(err))
					return updated, fmt.Errorf("failed to update CNAME record %s: %w", recRR.Name, err)
				}
			}
			updated = append(updated, libdns.RR{
				Type: "CNAME",
				Name: strings.TrimSuffix(*record.Name, "."+legitzone),
				Data: *record.Canonical,
			})
		case "TXT":
			record, err := objMgr.GetTXTRecord(p.View, recRR.Name)
			if err != nil {
				record, err = objMgr.CreateTXTRecord(p.View, recRR.Name+"."+legitzone, recRR.Data, uint32(recRR.TTL.Seconds()), true, "", nil)
				if err != nil {
					p.log().Error("failed to create TXT record", zap.String("name", recRR.Name), zap.Error(err))
					return updated, fmt.Errorf("failed to create TXT record %s: %w", recRR.Name, err)
				}
			} else {
				record, err = objMgr.UpdateTXTRecord(record.Ref, *record.Name, recRR.Data, *record.Ttl, *record.UseTtl, *record.Comment, record.Ea)
				if err != nil {
					p.log().Error("failed to update TXT record", zap.String("name", recRR.Name), zap.Error(err))
					return updated, fmt.Errorf("failed to update TXT record %s: %w", recRR.Name, err)
				}
			}
			updated = append(updated, libdns.RR{
				Type: "TXT",
				Name: strings.TrimSuffix(*record.Name, "."+legitzone),
				Data: *record.Text,
			})
		}
	}

	p.log().Info("set records", zap.String("zone", zone), zap.Int("updated", len(updated)))
	return updated, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(_ context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	p.log().Info("deleting records", zap.String("zone", zone), zap.Int("count", len(records)))
	var deleted []libdns.Record

	objMgr, err := p.getObjectManager()
	if err != nil {
		p.log().Error("failed to get object manager", zap.Error(err))
		return nil, fmt.Errorf("failed to get object manager: %w", err)
	}

	var legitzone = strings.TrimSuffix(zone, ".")

	for i := range records {
		var rec = records[i]
		var recRR = rec.RR()
		switch recRR.Type {
		case "CNAME":
			record, err := objMgr.GetCNAMERecord(p.View, "", recRR.Name+"."+legitzone)
			if err != nil {
				p.log().Error("failed to get CNAME record for deletion", zap.String("name", recRR.Name), zap.Error(err))
				return deleted, fmt.Errorf("failed to get CNAME record %s: %w", recRR.Name, err)
			}
			_, err = objMgr.DeleteCNAMERecord(record.Ref)
			if err != nil {
				p.log().Error("failed to delete CNAME record", zap.String("name", recRR.Name), zap.Error(err))
				return deleted, fmt.Errorf("failed to delete CNAME record %s: %w", recRR.Name, err)
			}
			deleted = append(deleted, libdns.RR{
				Type: "CNAME",
				Name: strings.TrimSuffix(*record.Name, "."+legitzone),
				Data: *record.Canonical,
			})
		case "TXT":
			record, err := objMgr.GetTXTRecord(p.View, recRR.Name+"."+legitzone)
			if err != nil {
				p.log().Error("failed to get TXT record for deletion", zap.String("name", recRR.Name), zap.Error(err))
				return deleted, fmt.Errorf("failed to get TXT record %s: %w", recRR.Name, err)
			}
			_, err = objMgr.DeleteTXTRecord(record.Ref)
			if err != nil {
				p.log().Error("failed to delete TXT record", zap.String("name", recRR.Name), zap.Error(err))
				return deleted, fmt.Errorf("failed to delete TXT record %s: %w", recRR.Name, err)
			}
			deleted = append(deleted, libdns.RR{
				Type: "TXT",
				Name: strings.TrimSuffix(*record.Name, "."+legitzone),
				Data: *record.Text,
			})
		}
	}

	p.log().Info("deleted records", zap.String("zone", zone), zap.Int("deleted", len(deleted)))
	return deleted, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)

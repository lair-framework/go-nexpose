/*Package nexpose parses Nexpose XML data into a similary formed struct.*/
package nexpose

import (
	"encoding/xml"
)

// NexposeRun contains all the data for a single nexpose scan.
type NexposeRun struct {
	Address     string        `xml:"address,attr"`
	Status      string        `xml:"status,attr"`
	Name        []HostName    `xml:"names"`
	Fingerprint []Fingerprint `xml:"fingerprints>os"`
	Test        []Test        `xml:"tests>test"`
	Endpoint    []Endpoint    `xml:"endpoints>endpoint"`
}

// This struct stores hostnames in an array as there can be multiple
type HostName struct {
	Name string `xml:"name"`
}

// This struct stores details about both OS and Service fingerprints
type Fingerprint struct {
	Certainty   string `xml:"certainty,attr"`
	DeviceClass string `xml:"device-class,attr"`
	Vendor      string `xml:"vendor,attr"`
	Family      string `xml:"family,attr"`
	Product     string `xml:"product,attr"`
	Version     string `xml:"version,attr"`
}

// This struct stores details about the vulnerability and evidence
type Test struct {
	Id                  string      `xml:"id,attr"`
	Key                 string      `xml:"key,attr"`
	Status              string      `xml:"status,attr"`
	ScanId              string      `xml:"scan-id,attr"`
	VulnerableSince     string      `xml:"vulnerable-since,attr"`
	PciComplianceStatus string      `xml:"pci-compliance-status,attr"`
	Paragraph           []Paragraph `xml:"Paragraph"`
}

// Nexpose embeds scan data in Paragraph sections w/ both chardata and innerxml types
type Paragraph struct {
	Paragraph     string          `xml:",chardata"`
	UnorderedList []UnorderedList `xml:"UnorderedList>ListItem"`
	SubParagraph  []Paragraph     `xml:"Paragraph"`
}

// Nexpose embeds scan data in Paragraph sections w/ both chardata and innerxml types
type UnorderedList struct {
	ListItem string `xml:",innerxml"`
}

// This struct stores details about the general protocol/port/service
type Endpoint struct {
	Protocol string    `xml:"protocol,attr"`
	Port     string    `xml:"port,attr"`
	Status   string    `xml:"status,attr"`
	Service  []Service `xml:"services>service"`
}

// This struct stores details about the the actual service
type Service struct {
	Name          string          `xml:"name,attr"`
	Fingerprint   []Fingerprint   `xml:"fingerprints>fingerprint"`
	Configuration []Configuration `xml:"configuration>config"`
	Test          []Test          `xml:"tests>test"`
}

// This struct stores details about the service configuration
type Configuration struct {
	Name   string `xml:"name,attr"`
	Config string `xml:",chardata"`
}

// Parse takes a byte array of nmap xml data and unmarshals it into an
// NexposeRun struct. All elements are returned as strings, it is up to the caller
// to check and cast them to the proper type.
func Parse(content []byte) (*NexposeRun, error) {
	r := &NexposeRun{}
	err := xml.Unmarshal(content, r)
	if err != nil {
		return r, err
	}
	return r, nil
}

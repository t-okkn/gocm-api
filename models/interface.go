package models

type Subject struct {
	CommonName   string `json:"common_name" binding:"required"`
	Country      string `json:"country"`
	State        string `json:"state"`
	Locality     string `json:"locality"`
	Organization string `json:"organization"`
}

type NewCACertRequest struct {
	Subject             Subject `json:"subject" binding:"required"`
	PrivateKeyAlgorithm string  `json:"private_key_algorithm" binding:"required"`
	Bits                int     `json:"bits" binding:"required"`
}

type NewServerCertRequest struct {
	CommonName     string   `json:"common_name" binding:"required"`
	SubjectAltName []string `json:"subject_alt_name" binding:"required"`
}

type NewClientCertRequest struct {
	CommonName string `json:"common_name" binding:"required"`
}

type NewCAResponse struct {
	CAID     string `json:"ca_id"`
	Password string `json:"password"`
}

type NewCertResponse struct {
	CAID       string `json:"ca_id"`
	Serial     uint32 `json:"serial"`
	CommonName string `json:"common_name"`
}

type CAInfoResponse struct {
	CAID         string         `json:"ca_id"`
	ValidCerts   []CertSummary  `json:"valid_certs"`
	InvalidCerts []SlimCertData `json:"invalid_certs"`
}

type CertsResponse struct {
	CAID       string        `json:"ca_id"`
	Serial     uint32        `json:"serial"`
	CommonName string        `json:"common_name"`
	Certs      []CertSummary `json:"certs"`
}

type AuditResponse struct {
	CAID         string        `json:"ca_id"`
	Days         int           `json:"days"`
	ExpectedDate string        `json:"expected_date"`
	Certs        []CertSummary `json:"certs"`
}

type CertSummary struct {
	Serial         uint32 `json:"serial"`
	CommonName     string `json:"common_name"`
	CertType       string `json:"cert_type"`
	Created        string `json:"created"`
	ExpirationDate string `json:"expiration_date"`
}

type DBRequest struct {
	Serial     uint32 `json:"serial"`
	CommonName string `json:"common_name"`
}

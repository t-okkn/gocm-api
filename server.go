package main

import (
	"crypto/x509/pkix"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-gorp/gorp"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"

	"gocm-api/cert"
	"gocm-api/db"
	"gocm-api/models"
)

const (
	CA_PASSWORD string = "GOCM-CA-PASSWORD"
)

var (
	repo *db.Repository

	// a-z, A-Z, 0-9, *-._, SP
	allowRune = []rune{
		32, 42, 45, 46, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 65, 66,
		67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82,
		83, 84, 85, 86, 87, 88, 89, 90, 95, 97, 98, 99, 100, 101, 102,
		103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
		115, 116, 117, 118, 119, 120, 121, 122,
	}
)

/*
// memo:
// CA証明書新規：何も証明書がない or 有効期限切れの証明書しかない状態で作成
// CA証明書更新：有効な証明書が1枚だけ存在する状態で破棄＆新規作成
// その他証明書新規：何もせず新規作成
// その他証明書更新：特定の有効な証明書を破棄＆新規作成
*/

/*
<summary>: 待ち受けるサーバのルーターを定義します

	<remark>: httpHandlerを受け取る関数にそのまま渡せる
*/
func SetupRouter() *gin.Engine {
	router := gin.Default()
	v1 := router.Group("v1")

	v1.POST("/ca", newCA)
	v1.GET("/ca/:id", getCAInfo)
	v1.DELETE("/ca/:id", destroyCA)

	v1.GET("/ca/:id/audit", auditAllCerts)

	certs := v1.Group("certs")

	certs.POST("/ca/:id", newCACert)
	certs.GET("/ca/:id", getCACert)
	certs.PUT("/ca/:id", updateCACert)

	certs.POST("/server/:id", newServerCert)
	certs.GET("/server/:id", getServerCert)
	certs.PUT("/server/:id/:serial", updateServerCert)

	certs.POST("/client/:id", newClientCert)
	certs.GET("/client/:id", getClientCert)
	certs.PUT("/client/:id/:serial", updateClientCert)

	repo = initDB()

	return router
}

func newCA(c *gin.Context) {
	obj, err := uuid.NewRandom()

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	id := obj.String()
	password, err := cert.GeneratePassword()

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	hash, err := cert.GetHashedPassword(password)

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	cainfo := models.TranCAInfo{
		Id:       id,
		Password: hash,
		Created:  getNowString(),
	}

	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	if err := repo.InsertCAInfo(cainfo); err != nil {
		c.JSON(http.StatusInternalServerError, errFailedOperateData)
		c.Abort()
		return
	}

	c.JSON(http.StatusCreated, models.NewCAResponse{
		CAID:     id,
		Password: password,
	})
}

func getCAInfo(c *gin.Context) {
	id_prm := c.Param("id")

	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	cainfo, err := repo.GetCAInfo(id_prm)

	if err != nil {
		c.JSON(http.StatusNotFound, errInvalidURL)
		c.Abort()
		return
	}

	caid := cainfo.Id
	certs, err := repo.GetCASummary(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	response := models.CAInfoResponse{CAID: caid}
	response.ValidCerts = make([]models.CertSummary, 0, len(certs))
	response.InvalidCerts = make([]models.SlimCertData, 0, len(certs))

	if len(certs) == 0 {
		c.JSON(http.StatusOK, response)
		return
	}

	for _, cert := range certs {
		expire := getParsedTime(cert.ExpirationDate)

		if cert.IsRevoked == 1 || expire.Before(time.Now()) {
			response.InvalidCerts = append(response.InvalidCerts, cert)

		} else {
			summary := models.CertSummary{
				Serial:         cert.Serial,
				CommonName:     cert.CommonName,
				CertType:       cert.CertType,
				Created:        cert.Created,
				ExpirationDate: cert.ExpirationDate,
			}
			response.ValidCerts = append(response.ValidCerts, summary)
		}
	}

	c.JSON(http.StatusOK, response)
}

func destroyCA(c *gin.Context) {
	id_prm := c.Param("id")

	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	cainfo, err := repo.GetCAInfo(id_prm)

	if err != nil {
		c.JSON(http.StatusNotFound, errInvalidURL)
		c.Abort()
		return
	}

	caid := cainfo.Id
	password := c.GetHeader(CA_PASSWORD)
	err = cert.VerifyPassword(cainfo.Password, password)

	if err != nil {
		// パスワードの照合エラーについては、アクセス権限なしとする
		c.JSON(http.StatusForbidden, errFailedAccess)
		c.Abort()
		return
	}

	if err := repo.DestroyCA(caid, cainfo); err != nil {
		c.JSON(http.StatusInternalServerError, errFailedOperateData)
		c.Abort()
		return
	}

	c.Status(http.StatusNoContent)
}

func auditAllCerts(c *gin.Context) {
	id_prm := c.Param("id")
	days_qry := c.DefaultQuery("days", "30")

	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	cainfo, err := repo.GetCAInfo(id_prm)

	if err != nil {
		c.JSON(http.StatusNotFound, errInvalidURL)
		c.Abort()
		return
	}

	caid := cainfo.Id
	certs, err := repo.AuditCertData(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	days, err := strconv.Atoi(days_qry)

	// 不正な文字列、1未満365より大きい数は強制的に30日
	if err != nil || (days < 1 || days > 365) {
		days = 30
	}

	expected := time.Now().AddDate(0, 0, days)
	response := models.AuditResponse{
		CAID:         caid,
		Days:         days,
		ExpectedDate: expected.Format(cert.DT_FORMAT),
	}
	response.Certs = make([]models.CertSummary, 0, len(certs))

	if len(certs) == 0 {
		c.JSON(http.StatusOK, response)
		return
	}

	for _, cert := range certs {
		expire := getParsedTime(cert.ExpirationDate)

		// 現在からdays日後の時間が期限前であれば無視
		if expected.Before(expire) {
			continue
		}

		summary := models.CertSummary{
			Serial:         cert.Serial,
			CommonName:     cert.CommonName,
			CertType:       cert.CertType,
			Created:        cert.Created,
			ExpirationDate: cert.ExpirationDate,
		}

		response.Certs = append(response.Certs, summary)
	}

	c.JSON(http.StatusOK, response)
}

func newCACert(c *gin.Context) {
	id_prm := c.Param("id")
	var req models.NewCACertRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errInvalidRequestedData)
		c.Abort()
		return
	}

	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	cainfo, err := repo.GetCAInfo(id_prm)

	if err != nil {
		c.JSON(http.StatusNotFound, errInvalidURL)
		c.Abort()
		return
	}

	caid := cainfo.Id
	capcs, err := repo.CheckCACert(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	cadata, err := repo.GetCACerts(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	if capcs != 0 {
		if len(cadata) == 1 {
			c.JSON(http.StatusConflict, errExistsValidCACert)
			c.Abort()
			return

		} else if len(cadata) > 1 {
			c.JSON(http.StatusInternalServerError, errInvalidCertStore)
			c.Abort()
			return
		}
	}

	password := c.GetHeader(CA_PASSWORD)
	err = cert.VerifyPassword(cainfo.Password, password)

	if err != nil {
		// パスワードの照合エラーについては、アクセス権限なしとする
		c.JSON(http.StatusForbidden, errFailedAccess)
		c.Abort()
		return
	}

	var cakey cert.PrivateKey

	switch strings.ToUpper(req.PrivateKeyAlgorithm) {
	case "RSA":
		if req.Bits != 2048 && req.Bits != 4096 {
			c.JSON(http.StatusBadRequest, errIncompatibleBits)
			c.Abort()
			return
		}

		cakey, err = cert.GenerateRSAKey(req.Bits)

	case "ECDSA":
		if req.Bits != 256 && req.Bits != 384 && req.Bits != 521 {
			c.JSON(http.StatusBadRequest, errIncompatibleBits)
			c.Abort()
			return
		}

		cakey, err = cert.GenerateECDSAKey(req.Bits)

	case "ED25519":
		cakey, err = cert.GenerateED25519Key()

	default:
		c.JSON(http.StatusBadRequest, errInvalidAlgorithm)
		c.Abort()
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	serial := uint32(1)

	if capcs != 0 && len(cadata) == 0 {
		max, err := repo.GetMaxSerialNumber(caid)

		if err != nil {
			c.JSON(http.StatusInternalServerError, errFailedGetData)
			c.Abort()
			return
		}

		serial = uint32(max) + 1
	}

	cert_req := &cert.CreateCACertRequest{
		CAID:       caid,
		PrivateKey: cakey,
		Subject:    toPkixName(req.Subject),
		Serial:     serial,
	}

	cacert, err := cert.CreateCACert(cert_req)

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	db_cacert, err := cacert.TranCertificate(password)

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	if err := repo.InsertCert(db_cacert); err != nil {
		c.JSON(http.StatusInternalServerError, errFailedOperateData)
		c.Abort()
		return
	}

	c.JSON(http.StatusCreated, models.NewCertResponse{
		CAID:       caid,
		Serial:     serial,
		CommonName: db_cacert.CommonName,
	})
}

func getCACert(c *gin.Context) {
	id_prm := c.Param("id")

	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	cainfo, err := repo.GetCAInfo(id_prm)

	if err != nil {
		c.JSON(http.StatusNotFound, errInvalidURL)
		c.Abort()
		return
	}

	caid := cainfo.Id
	cadata, err := repo.GetCACerts(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	if len(cadata) == 0 {
		c.JSON(http.StatusNotFound, errNotFoundValidCACert)
		c.Abort()
		return

	} else if len(cadata) > 1 {
		c.JSON(http.StatusInternalServerError, errInvalidCertStore)
		c.Abort()
		return
	}

	content_type := "application/x-pem-file; charset=utf-8"
	byte_data := []byte(cadata[0].CertData)
	c.Data(http.StatusOK, content_type, byte_data)

	// こちらでも問題はない
	// https://github.com/gin-gonic/gin/issues/468
	//c.Header("Content-Type", "application/x-pem-file")
	//c.String(http.StatusOK, cadata[0].CertData)
}

func updateCACert(c *gin.Context) {
	id_prm := c.Param("id")

	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	cainfo, err := repo.GetCAInfo(id_prm)

	if err != nil {
		c.JSON(http.StatusNotFound, errInvalidURL)
		c.Abort()
		return
	}

	caid := cainfo.Id
	capcs, err := repo.CheckCACert(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	cadata, err := repo.GetCACerts(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	if capcs == 0 || (capcs != 1 && len(cadata) == 0) {
		c.JSON(http.StatusNotFound, errNotFoundValidCACert)
		c.Abort()
		return
	}

	if len(cadata) > 1 {
		c.JSON(http.StatusInternalServerError, errInvalidCertStore)
		c.Abort()
		return
	}

	password := c.GetHeader(CA_PASSWORD)
	err = cert.VerifyPassword(cainfo.Password, password)

	if err != nil {
		// パスワードの照合エラーについては、アクセス権限なしとする
		c.JSON(http.StatusForbidden, errFailedAccess)
		c.Abort()
		return
	}

	cacert, err := cert.ToCertData(password, cadata[0])

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	max, err := repo.GetMaxSerialNumber(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	serial := uint32(max) + 1
	new_cacert, err := cacert.UpdateCert(serial, nil)

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	new_data, err := new_cacert.TranCertificate(password)

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	old_data := cadata[0]
	old_data.IsRevoked = 1
	old_data.Revoked = getNowString()

	if err := repo.UpdateCert(old_data, new_data); err != nil {
		c.JSON(http.StatusInternalServerError, errFailedOperateData)
		c.Abort()
		return
	}

	c.JSON(http.StatusCreated, models.NewCertResponse{
		CAID:       caid,
		Serial:     serial,
		CommonName: new_data.CommonName,
	})
}

func newServerCert(c *gin.Context) {
	id_prm := c.Param("id")
	var req models.NewServerCertRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errInvalidRequestedData)
		c.Abort()
		return
	}

	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	cainfo, err := repo.GetCAInfo(id_prm)

	if err != nil {
		c.JSON(http.StatusNotFound, errInvalidURL)
		c.Abort()
		return
	}

	caid := cainfo.Id
	cadata, err := repo.GetCACerts(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	if len(cadata) == 0 {
		c.JSON(http.StatusNotFound, errNotFoundValidCACert)
		c.Abort()
		return

	} else if len(cadata) > 1 {
		c.JSON(http.StatusInternalServerError, errInvalidCertStore)
		c.Abort()
		return
	}

	password := c.GetHeader(CA_PASSWORD)
	err = cert.VerifyPassword(cainfo.Password, password)

	if err != nil {
		// パスワードの照合エラーについては、アクセス権限なしとする
		c.JSON(http.StatusForbidden, errFailedAccess)
		c.Abort()
		return
	}

	ca, err := cert.ToCertData(password, cadata[0])

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	max, err := repo.GetMaxSerialNumber(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	serial := uint32(max) + 1
	cert_req := cert.CreateServerCertRequest{
		Subject: toPkixName(req.Subject),
		Serial:  serial,
	}

	cert_req.DNSNames = make([]string, 0, len(req.SubjectAltName))
	cert_req.IPAddresses = make([]net.IP, 0, len(req.SubjectAltName))
	cert_req.URIs = make([]*url.URL, 0, len(req.SubjectAltName))
	cert_req.EmailAddresses = make([]string, 0, len(req.SubjectAltName))

	for _, v := range req.SubjectAltName {
		switch {
		case strings.HasPrefix(v, "DNS:"):
			content := strings.Replace(v, "DNS:", "", 1)
			cert_req.DNSNames = append(cert_req.DNSNames, content)

		case strings.HasPrefix(v, "IP:"):
			content := strings.Replace(v, "IP:", "", 1)
			ipdata := net.ParseIP(content)

			if ipdata == nil {
				break
			}

			cert_req.IPAddresses = append(cert_req.IPAddresses, ipdata)

		case strings.HasPrefix(v, "URI:"):
			content := strings.Replace(v, "URI:", "", 1)
			urldata, err := url.Parse(content)

			if err != nil {
				break
			}

			cert_req.URIs = append(cert_req.URIs, urldata)

		case strings.HasPrefix(v, "email:"):
			content := strings.Replace(v, "email:", "", 1)
			cert_req.EmailAddresses = append(cert_req.EmailAddresses, content)
		}
	}

	if len(cert_req.DNSNames) == 0 && len(cert_req.IPAddresses) == 0 &&
		len(cert_req.URIs) == 0 && len(cert_req.EmailAddresses) == 0 {

		c.JSON(http.StatusBadRequest, errInvalidSANs)
		c.Abort()
		return
	}

	svcert, err := cert.CreateServerCert(&cert_req, ca)

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	db_cacert, err := svcert.TranCertificate(password)

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	if err := repo.InsertCert(db_cacert); err != nil {
		c.JSON(http.StatusInternalServerError, errFailedOperateData)
		c.Abort()
		return
	}

	c.JSON(http.StatusCreated, models.NewCertResponse{
		CAID:       caid,
		Serial:     serial,
		CommonName: db_cacert.CommonName,
	})
}

func getServerCert(c *gin.Context) {
	id_prm := c.Param("id")
	serial_qry := c.DefaultQuery("serial", "0")
	common_name := sanitize(c.DefaultQuery("cn", ""))

	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	cainfo, err := repo.GetCAInfo(id_prm)

	if err != nil {
		c.JSON(http.StatusNotFound, errInvalidURL)
		c.Abort()
		return
	}

	caid := cainfo.Id
	serial, err := strconv.ParseUint(serial_qry, 10, 0)

	if err != nil || serial > uint64(^uint32(0)) {
		c.JSON(http.StatusBadRequest, errInvalidSerial)
		c.Abort()
		return
	}

	db_req := models.DBRequest{
		Serial:     uint32(serial),
		CommonName: common_name,
	}

	svdata, err := repo.GetServerCerts(caid, db_req)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	if len(svdata) == 1 {
		c.Header("GOCM-REQUEST-SERIAL", fmt.Sprintf("%d", serial))
		c.Header("GOCM-REQUEST-CN", common_name)

		content_type := "application/x-pem-file; charset=utf-8"
		byte_data := []byte(svdata[0].CertData)
		c.Data(http.StatusOK, content_type, byte_data)

	} else {
		res := models.CertsResponse{
			CAID:       caid,
			Serial:     uint32(serial),
			CommonName: common_name,
		}
		res.Certs = make([]models.CertSummary, len(svdata))

		for i, data := range svdata {
			res.Certs[i] = models.CertSummary{
				Serial:         data.Serial,
				CommonName:     data.CommonName,
				CertType:       data.CertType,
				Created:        data.Created,
				ExpirationDate: data.ExpirationDate,
			}
		}

		c.JSON(http.StatusOK, res)
	}
}

func updateServerCert(c *gin.Context) {
	id_prm := c.Param("id")
	serial_prm := c.Param("serial")

	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	cainfo, err := repo.GetCAInfo(id_prm)

	if err != nil {
		c.JSON(http.StatusNotFound, errInvalidURL)
		c.Abort()
		return
	}

	caid := cainfo.Id
	cadata, err := repo.GetCACerts(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	if len(cadata) == 0 {
		c.JSON(http.StatusNotFound, errNotFoundValidCACert)
		c.Abort()
		return

	} else if len(cadata) > 1 {
		c.JSON(http.StatusInternalServerError, errInvalidCertStore)
		c.Abort()
		return
	}

	serial, err := strconv.ParseUint(serial_prm, 10, 0)

	if err != nil || serial > uint64(^uint32(0)) {
		c.JSON(http.StatusBadRequest, errInvalidSerial)
		c.Abort()
		return
	}

	db_req := models.DBRequest{
		Serial:     uint32(serial),
		CommonName: "",
	}

	svdata, err := repo.GetServerCerts(caid, db_req)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	if len(svdata) == 0 {
		c.JSON(http.StatusNotFound, errNotFoundValidServerCert)
		c.Abort()
		return

	} else if len(svdata) > 1 {
		c.JSON(http.StatusInternalServerError, errInvalidCertStore)
		c.Abort()
		return
	}

	password := c.GetHeader(CA_PASSWORD)
	err = cert.VerifyPassword(cainfo.Password, password)

	if err != nil {
		// パスワードの照合エラーについては、アクセス権限なしとする
		c.JSON(http.StatusForbidden, errFailedAccess)
		c.Abort()
		return
	}

	cacert, err := cert.ToCertData(password, cadata[0])

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	svcert, err := cert.ToCertData(password, svdata[0])

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	max, err := repo.GetMaxSerialNumber(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	new_serial := uint32(max) + 1
	new_svcert, err := svcert.UpdateCert(new_serial, cacert)

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	new_data, err := new_svcert.TranCertificate(password)

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	old_data := svdata[0]
	old_data.IsRevoked = 1
	old_data.Revoked = getNowString()

	if err := repo.UpdateCert(old_data, new_data); err != nil {
		c.JSON(http.StatusInternalServerError, errFailedOperateData)
		c.Abort()
		return
	}

	c.JSON(http.StatusCreated, models.NewCertResponse{
		CAID:       caid,
		Serial:     new_serial,
		CommonName: new_data.CommonName,
	})
}

func newClientCert(c *gin.Context) {
	id_prm := c.Param("id")
	var req models.NewClientCertRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errInvalidRequestedData)
		c.Abort()
		return
	}

	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	cainfo, err := repo.GetCAInfo(id_prm)

	if err != nil {
		c.JSON(http.StatusNotFound, errInvalidURL)
		c.Abort()
		return
	}

	caid := cainfo.Id
	cadata, err := repo.GetCACerts(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	if len(cadata) == 0 {
		c.JSON(http.StatusNotFound, errNotFoundValidCACert)
		c.Abort()
		return

	} else if len(cadata) > 1 {
		c.JSON(http.StatusInternalServerError, errInvalidCertStore)
		c.Abort()
		return
	}

	password := c.GetHeader(CA_PASSWORD)
	err = cert.VerifyPassword(cainfo.Password, password)

	if err != nil {
		// パスワードの照合エラーについては、アクセス権限なしとする
		c.JSON(http.StatusForbidden, errFailedAccess)
		c.Abort()
		return
	}

	ca, err := cert.ToCertData(password, cadata[0])

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	max, err := repo.GetMaxSerialNumber(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	serial := uint32(max) + 1
	subject := toPkixName(req.Subject)
	clcert, err := cert.CreateClientCert(serial, subject, ca)

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	db_cacert, err := clcert.TranCertificate(password)

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	if err := repo.InsertCert(db_cacert); err != nil {
		c.JSON(http.StatusInternalServerError, errFailedOperateData)
		c.Abort()
		return
	}

	c.JSON(http.StatusCreated, models.NewCertResponse{
		CAID:       caid,
		Serial:     serial,
		CommonName: db_cacert.CommonName,
	})
}

func getClientCert(c *gin.Context) {
	id_prm := c.Param("id")
	serial_qry := c.DefaultQuery("serial", "0")
	common_name := sanitize(c.DefaultQuery("cn", ""))

	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	cainfo, err := repo.GetCAInfo(id_prm)

	if err != nil {
		c.JSON(http.StatusNotFound, errInvalidURL)
		c.Abort()
		return
	}

	caid := cainfo.Id
	password := c.GetHeader(CA_PASSWORD)
	err = cert.VerifyPassword(cainfo.Password, password)

	if err != nil {
		// パスワードの照合エラーについては、アクセス権限なしとする
		c.JSON(http.StatusForbidden, errFailedAccess)
		c.Abort()
		return
	}

	serial, err := strconv.ParseUint(serial_qry, 10, 0)

	if err != nil || serial > uint64(^uint32(0)) {
		c.JSON(http.StatusBadRequest, errInvalidSerial)
		c.Abort()
		return
	}

	db_req := models.DBRequest{
		Serial:     uint32(serial),
		CommonName: common_name,
	}

	cldata, err := repo.GetClientCerts(caid, db_req)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	if len(cldata) == 1 {
		default_pin := string([]rune(getNowString())[:10])
		pin := sanitize(c.DefaultQuery("pin", default_pin))

		clcert, err := cert.ToCertData(password, cldata[0])

		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorMessage{
				Code:    "E501",
				Message: err.Error(),
			})
			c.Abort()
			return
		}

		byte_data, err := clcert.ToPkcs12(pin)

		if err != nil {
			c.JSON(http.StatusInternalServerError, ErrorMessage{
				Code:    "E501",
				Message: err.Error(),
			})
			c.Abort()
			return
		}

		c.Header("GOCM-REQUEST-SERIAL", fmt.Sprintf("%d", serial))
		c.Header("GOCM-REQUEST-CN", common_name)
		c.Header("GOCM-REQUEST-PIN", pin)

		content_type := "application/x-pkcs12"
		c.Data(http.StatusOK, content_type, byte_data)

	} else {
		res := models.CertsResponse{
			CAID:       caid,
			Serial:     uint32(serial),
			CommonName: common_name,
		}
		res.Certs = make([]models.CertSummary, len(cldata))

		for i, data := range cldata {
			res.Certs[i] = models.CertSummary{
				Serial:         data.Serial,
				CommonName:     data.CommonName,
				CertType:       data.CertType,
				Created:        data.Created,
				ExpirationDate: data.ExpirationDate,
			}
		}

		c.JSON(http.StatusOK, res)
	}
}

func updateClientCert(c *gin.Context) {
	id_prm := c.Param("id")
	serial_prm := c.Param("serial")

	if repo == nil {
		c.JSON(http.StatusServiceUnavailable, errCannotConnectDB)
		c.Abort()
		return
	}

	cainfo, err := repo.GetCAInfo(id_prm)

	if err != nil {
		c.JSON(http.StatusNotFound, errInvalidURL)
		c.Abort()
		return
	}

	caid := cainfo.Id
	cadata, err := repo.GetCACerts(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	if len(cadata) == 0 {
		c.JSON(http.StatusNotFound, errNotFoundValidCACert)
		c.Abort()
		return

	} else if len(cadata) > 1 {
		c.JSON(http.StatusInternalServerError, errInvalidCertStore)
		c.Abort()
		return
	}

	serial, err := strconv.ParseUint(serial_prm, 10, 0)

	if err != nil || serial > uint64(^uint32(0)) {
		c.JSON(http.StatusBadRequest, errInvalidSerial)
		c.Abort()
		return
	}

	db_req := models.DBRequest{
		Serial:     uint32(serial),
		CommonName: "",
	}

	cldata, err := repo.GetClientCerts(caid, db_req)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	if len(cldata) == 0 {
		c.JSON(http.StatusNotFound, errNotFoundValidClientCert)
		c.Abort()
		return

	} else if len(cldata) > 1 {
		c.JSON(http.StatusInternalServerError, errInvalidCertStore)
		c.Abort()
		return
	}

	password := c.GetHeader(CA_PASSWORD)
	err = cert.VerifyPassword(cainfo.Password, password)

	if err != nil {
		// パスワードの照合エラーについては、アクセス権限なしとする
		c.JSON(http.StatusForbidden, errFailedAccess)
		c.Abort()
		return
	}

	cacert, err := cert.ToCertData(password, cadata[0])

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	clcert, err := cert.ToCertData(password, cldata[0])

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	max, err := repo.GetMaxSerialNumber(caid)

	if err != nil {
		c.JSON(http.StatusInternalServerError, errFailedGetData)
		c.Abort()
		return
	}

	new_serial := uint32(max) + 1
	new_clcert, err := clcert.UpdateCert(new_serial, cacert)

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	new_data, err := new_clcert.TranCertificate(password)

	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorMessage{
			Code:    "E501",
			Message: err.Error(),
		})
		c.Abort()
		return
	}

	old_data := cldata[0]
	old_data.IsRevoked = 1
	old_data.Revoked = getNowString()

	if err := repo.UpdateCert(old_data, new_data); err != nil {
		c.JSON(http.StatusInternalServerError, errFailedOperateData)
		c.Abort()
		return
	}

	c.JSON(http.StatusCreated, models.NewCertResponse{
		CAID:       caid,
		Serial:     new_serial,
		CommonName: new_data.CommonName,
	})
}

/*
<summary>: DBとの接続についての初期処理
*/
func initDB() *db.Repository {
	driver, dsn, err := db.GetDataSourceName()
	if err != nil {
		fmt.Println("E001 :", err)
		return nil
	}

	var dbmap *gorp.DbMap

	switch driver {
	case "mysql":
		op, _ := sql.Open(driver, dsn)
		dial := gorp.MySQLDialect{Engine: "InnoDB", Encoding: "utf8mb4"}

		dbmap = &gorp.DbMap{Db: op, Dialect: dial, ExpandSliceArgs: true}
		models.MapStructsToTables(dbmap)
	}

	return db.NewRepository(dbmap)
}

func toPkixName(subject models.Subject) pkix.Name {
	data := pkix.Name{
		CommonName: subject.CommonName,
	}

	if subject.Country != "" {
		data.Country = []string{subject.Country}
	}

	if subject.State != "" {
		data.Province = []string{subject.State}
	}

	if subject.Locality != "" {
		data.Locality = []string{subject.Locality}
	}

	if subject.Organization != "" {
		data.Organization = []string{subject.Organization}
	}

	return data
}

func sanitize(input string) string {
	var sb strings.Builder
	sb.Grow(len(input))

	for _, char := range input {
		for _, r := range allowRune {
			if char == r {
				sb.WriteRune(char)
				break
			}
		}
	}

	return sb.String()
}

/*
<summary>: SQLに登録されている文字列型の時間をtime.Time型へ変換します
*/
func getParsedTime(strTime string) time.Time {
	loc, _ := time.LoadLocation("Asia/Tokyo")

	t, err := time.ParseInLocation(cert.DT_FORMAT, strTime, loc)
	if err != nil {
		return time.Date(1970, 1, 1, 9, 0, 0, 0, loc)
	}

	return t
}

/*
<summary>: 現在時刻を示す文字列を取得します
*/
func getNowString() string {
	return time.Now().Format(cert.DT_FORMAT)
}

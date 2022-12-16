package main

type ErrorMessage struct {
	Code    string `json:"error"`
	Message string `json:"message"`
}

var (
	errCannotConnectDB = ErrorMessage{
		Code   : "E001",
		Message: "DBと接続できません",
	}

	errFailedOperateData = ErrorMessage{
		Code   : "E002",
		Message: "データの操作に失敗しました",
	}

	errFailedGetData = ErrorMessage{
		Code   : "E003",
		Message: "データの取得に失敗しました",
	}

	errInvalidRequestedData = ErrorMessage{
		Code   : "E101",
		Message: "リクエストされたデータが不正です",
	}

	errInvalidAlgorithm = ErrorMessage{
		Code   : "E102",
		Message: "不正なアルゴリズムが指定されています",
	}

	errIncompatibleBits = ErrorMessage{
		Code   : "E103",
		Message: "指定されたアルゴリズムに対して非対応のビット数です",
	}

	errInvalidURL = ErrorMessage{
		Code   : "E104",
		Message: "リクエストされたURLが正しくありません",
	}

	errInvalidSANs = ErrorMessage{
		Code   : "E105",
		Message: "Subject AltNameとして有効なデータが存在しませんでした",
	}

	errInvalidSerial = ErrorMessage{
		Code   : "E106",
		Message: "Serial値が有効な数値ではありません",
	}

	errExistsValidCACert = ErrorMessage{
		Code   : "E201",
		Message: "既に有効なCA証明書が存在しています",
	}

	errNotFoundValidCACert = ErrorMessage{
		Code   : "E202",
		Message: "有効なCA証明書が存在しません",
	}

	errInvalidCertStore = ErrorMessage{
		Code   : "E203",
		Message: "証明書ストアが不正な状態になっています",
	}

	errNotFoundValidServerCert = ErrorMessage{
		Code   : "E204",
		Message: "有効なサーバ証明書が存在しません",
	}

	errNotFoundValidClientCert = ErrorMessage{
		Code   : "E205",
		Message: "有効なクライアント証明書が存在しません",
	}

	errFailedAccess = ErrorMessage{
		Code   : "E301",
		Message: "証明書へのアクセス権限がありません",
	}
)
module github.com/ergochat/ergo

go 1.25

require (
	code.cloudfoundry.org/bytefmt v0.0.0-20200131002437-cf55d5288a48
	github.com/GehirnInc/crypt v0.0.0-20200316065508-bb7000b8a962
	github.com/docopt/docopt-go v0.0.0-20180111231733-ee0de3bc6815
	github.com/ergochat/confusables v0.0.0-20201108231250-4ab98ab61fb1
	github.com/ergochat/go-ident v0.0.0-20230911071154-8c30606d6881
	github.com/ergochat/irc-go v0.5.0-rc2
	github.com/go-sql-driver/mysql v1.7.0
	github.com/gofrs/flock v0.8.1
	github.com/nbd-wtf/go-nostr v0.52.0
	github.com/okzk/sdnotify v0.0.0-20180710141335-d9becc38acbd
	github.com/tidwall/btree v1.4.2 // indirect
	github.com/tidwall/buntdb v1.3.2
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/grect v0.1.4 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/rtred v0.1.2 // indirect
	github.com/tidwall/tinyqueue v0.1.1 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.0.2
	golang.org/x/crypto v0.38.0
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/term v0.32.0
	golang.org/x/text v0.25.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/emersion/go-msgauth v0.7.0
	github.com/ergochat/webpush-go/v2 v2.0.0
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/gorilla/websocket v1.5.3
)

require (
	github.com/ImVexed/fasturl v0.0.0-20230304231329-4e41488060f3 // indirect
	github.com/btcsuite/btcd/btcec/v2 v2.3.4 // indirect
	github.com/btcsuite/btcd/btcutil v1.1.5 // indirect
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0 // indirect
	github.com/bytedance/sonic v1.13.1 // indirect
	github.com/bytedance/sonic/loader v0.2.4 // indirect
	github.com/cloudwego/base64x v0.1.5 // indirect
	github.com/coder/websocket v1.8.12 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.2.10 // indirect
	github.com/mailru/easyjson v0.9.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/puzpuzpuz/xsync/v3 v3.5.1 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	golang.org/x/arch v0.15.0 // indirect
	golang.org/x/exp v0.0.0-20250305212735-054e65f0b394 // indirect
)

replace github.com/gorilla/websocket => github.com/ergochat/websocket v1.4.2-oragono1

replace github.com/xdg-go/scram => github.com/ergochat/scram v1.0.2-ergo1

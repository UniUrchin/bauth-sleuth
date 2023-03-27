# bauth-sleuth

流れてくるネットワークトラフィックをキャプチャして、BASIC認証時のHTTP通信からBASE64でエンコードされたユーザ名とパスワードを抜き取ることができるスクリプト。

とっても怒られるので、くれぐれも勤め先のネットワークをキャプチャしたりしないように!!

## Requirement

- Cargo 1.52

## How to Build & Execute

- ビルド方法

```
$ cargo build
```

- scp-metatitle-checkerの実行(キャプチャするインターフェースを引数に指定する必要がある)

```
$ ./target/debug/bauth-sleuth <インターフェース名>
```

## Usage

bauth-sleuthを実行した状態でBASIC認証の通信を検知すると、デコードされた機密情報をリアルタイムに表示してくれる。

```
===========================
 - BasicAuth Information -
===========================
Timestamp: 2023/03/27 19:10:37
Request_URL: http:/***.***.***.com/*****************.html
Username: ******
password: ***********
```
BlackJumboDog
=============
fork from https://github.com/furuya02/bjd5

## 追加機能
HTTP proxyにリクエスト元プログラム制限機能を追加します。

### 概要
HTTP proxyリクエストの送信元プログラム名をチェックして、
ホワイトリストにあるプログラムからのリクエストのみを中継する機能を、
BlackJumboDogのHTTP proxyに追加したものです。

socket接続元ポート番号から、該当するプロセスIDを取得して、
プロセスIDからプログラム名(フルパス)を取得します。
localhostで動かす想定です。

### 背景
会社内ネットワークからのインターネットアクセスは認証proxy経由。
マルウェア対策としてproxy認証が必須になっているのですが、
proxy認証用ユーザIDとパスワードを、
ユーザまたは機器ごと、各ツール/プログラムごとに設定する必要があって、
開発環境構築時など、生産性が数%は落ちている気がします。

なので、たいていは、上位proxyとして認証proxyを設定した、
認証無しproxy(polipo等)を各PCで動かして使いたくなるのですが、
そうするとマルウェア対策を弱めている形になるのであまり良くない気もします。
(システムのproxy設定を参照するマルウェアがインターネットアクセス可能になるので)

そこで、マルウェア対策を弱めずに、
認証用のID/パスワードを各ツール/プログラムごとに設定する繁雑さを減らす目的で
試作しました。
(ただし、各ツール/プログラムに(認証無し)proxy設定(localhost:8080等)をする必要はあり。)

### セットアップ
* [BlackJumboDog v6.2.0](https://forest.watch.impress.co.jp/library/software/blackjmbdog/)をインストール。
* BlackJumboDogのインストールディレクトリにある、
  ProxyHttpServer.dllとBJD.Lang.txtファイルを、
  アクセス元プログラム制限機能追加版で上書き。
  * [ProxyHttpServer.dll](https://github.com/deton/bjd5/releases)
  * [BJD.Lang.txt](https://github.com/deton/bjd5/blob/master/SetupFiles/BJD.Lang.txt)

### 使い方
BJD.exe起動後、「オプション」→「プロキシサーバ」→「ブラウザ」ダイアログで、
「プロキシサーバ[Browser]を使用する」。
「ACL」タブで127.0.0.1を許可。
「アクセス元プログラム制限」タブで、許可するプログラムのフルパスを追加。

プログラムのフルパスは、アクセス元プログラムでBJDをproxyサーバに指定して
リクエストを発行した際の、BJD側ログからコピーするのが早いかも。

例: Git Bashのcurlの場合、
`curl -x localhost:8080 http://www.google.co.jp`
を実行。フルパスは、
`C:\Program Files\Git\mingw64\bin\curl.exe`

### TODO
* proxyリクエストを受けた時に、許可するかダイアログ表示して選択可能にする。
* 常に許可/禁止、以外の設定を可能にする。
  * 今回だけ許可
  * 今から5分以内のみ許可
  * 今から1時間は禁止
* リクエスト元の親プロセスまでチェックする。
  HTTPリクエストをcurl等を使って行うプロセスに対応できるようにするため。

### 参考: BlackJumboDog変更以外の実現方法案
* [.NET Core CLR版BlackJumboDog](https://github.com/darkcrash/bjd5)
* [Windows用Squid](http://squid.diladele.com/)
  でurl_rewrite_programとして作成しようとしてみたが、
  stdinから何も読めないので断念
* Windows版[polipo](https://github.com/jech/polipo)はredirector未対応。
  polipoに対するredirector対応と接続元ポート番号を渡す変更が必要になるので見送り。
* [goproxy](https://github.com/elazarl/goproxy)ライブラリを使ってproxyサーバ自作する方法は、proxyサーバ本体機能をいろいろ作る必要がありそうだったので見送り。
* [3proxy](http://3proxy.ru)のプラグインDLLとして作成する方法は、
  C/C++で書くのが少しおっくうだったのと、3proxy自体の設定ファイルがわかりにくい気がしたので見送り。
* [Delegatedのドキュメント](https://i-red.info/docs/Manual.htm?AUTHORIZER)を見たが、
  外部コマンドに接続元ポート番号を渡す方法を見つけられなかったので見送り。

## 参考
* [Windowsファイアウォールでアウトバンド通信をブロックする](http://www.atmarkit.co.jp/fwin2k/win2ktips/892vistafwout/vistafwout.html)。送信の規則
* [LuLu - 外向きのネットワークトラフィックを監視するファイアウォール](https://www.moongift.jp/2018/02/lulu-%e5%a4%96%e5%90%91%e3%81%8d%e3%81%ae%e3%83%8d%e3%83%83%e3%83%88%e3%83%af%e3%83%bc%e3%82%af%e3%83%88%e3%83%a9%e3%83%95%e3%82%a3%e3%83%83%e3%82%af%e3%82%92%e7%9b%a3%e8%a6%96%e3%81%99%e3%82%8b/)
* Windows用ローカルプロキシ。自動設定: [認証プロキシ爆発しろ！](http://ipponshimeji.cocolog-nifty.com/blog/2017/01/post-0ce6.html)

## License
[Apache License Version 2.0](LICENSE)

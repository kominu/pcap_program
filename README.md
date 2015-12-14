# pcap_program
packet capture program(C++)

## 概要
パケットをキャプチャし、UDPでローカルの可視化プログラムに送信する
可視化プログラムから送られてくるUDPパケットを元に送信先のポート、IPを決める
そのため可視化プログラムが起動するまでキャプチャは開始されない

## 準備
* libpcap-devel
* mysql
* mysql-server
* mysql-devel 
をインストール

iptablesの設定に 
-A INPUT -p udp --dport 19998 -j ACCEPT 
を追加

gitを使う際は 
git checkout -b develop 
で作業用ブランチを作成 

githubにpushするには 
git config --global でユーザ名とemail登録 
git remote set-url git@github.com:kominu/pcap\_program 
のあと、ssh-keygen -t rsaで公開鍵を作成、githubに登録

_ログの設定_
iptablesの設定の最後に 
-N LOGGING 
-A LOGGING -j LOG --log-prefix "DROP: " --log-level=info 
-A LOGGING -j DROP 
-A INPUT -j LOGGING 
を加える 

rsyslog.confに 
kern.info	/var/log/iptables.log 
を追加 

/etc/logrotate.d/iptables 
に設定を記述 

その後service restart

## オプション
* -s
サンプリングモード。後ろに数値をつければ1/xでサンプリングする

## リアルタイム・読み込みについて
* オンラインモード
インライン引数を入力しなければオンラインモードで起動する
リアルタイムな監視を行う

* オフラインモード
読み込みファイル、IPアドレスをインライン引数として入力するとオフラインモードで起動する
pcapファイルの読み込みが可能

## MySQL
接続できれば使用、できなければ使用しない

## 書き出しについて
cap_data.csv、log.pcapに最新の結果を出力

# ip_analysis program

## 概要
pcapファイルを読み込み、通信頻度の高いipアドレスを10個出力する。
通信先サーバが複数ある場合にこのプログラムを使ってどのサーバに関わる情報を可視化するかを決める

## 出力について
標準出力以外では、出力結果はresultディレクトリにファイル名_ip.txtで格納される

## オプション
* -i
詳細表示モード
 

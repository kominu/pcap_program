# pcap_program
packet capture program(C++)

## 概要
パケットをキャプチャし、UDPでローカルの可視化プログラムに送信する
可視化プログラムから送られてくるUDPパケットを元に送信先のポート、IPを決める
そのため可視化プログラムが起動するまでキャプチャは開始されない

## モードについて
* オンラインモード
インライン引数を入力しなければオンラインモードで起動する
リアルタイムな監視を行う

* オフラインモード
読み込みファイル、IPアドレスをインライン引数として入力するとオフラインモードで起動する
pcapファイルの読み込みが可能

* __どちらもsu権限が必要__


import qrcode

qr = qrcode.make('hello world')
qr.save('myQR.png')
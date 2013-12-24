#To start $PWD/test should contain
#containercert.pem, containerkey.pem and certificates dir with CA data

export PYTHONPATH=$PWD:$PYTHONPATH
python gridhttpserver/werk.py -c "$PWD/test/containercert.pem" -k "$PWD/test/containerkey.pem" --ssl_capath "$PWD/test/certificates" -w test.test_hello:make_app

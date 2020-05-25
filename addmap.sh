
#!/bin/bash
echo "add map ./map 192.168.124.212 ft_group" | sudo socat stdio /var/run/haproxy.sock

echo "add map ./map 192.168.123.3 frontend_group" | sudo socat stdio /var/run/haproxy.sock


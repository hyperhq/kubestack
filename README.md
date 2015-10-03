# OpenStack Network Provider for Kubernetes
 
KubeStack is an OpenStack network provider for kubernetes. KubeStack is devided into two functions:

* kubestack running on the same host with kube-controller-manager, which provides network management by openstack
* kubestack running on each minion host, which setups container's network interfaces

## How to run it

Notes: You need a working OpenStack and Kubernetes before deploying kubestack.


```
cd $GOPATH
git clone https://github.com/hyperhq/kubestack.git
cd kubestack
make && make install
```

Configure openstack authorization properties in `/etc/kubestack.conf`:

```
[Global]
auth-url = http://192.168.33.33:5000/v2.0
username = admin
password = admin
tenant-name = admin
region = RegionOne
ext-net-id = <Your-external-network-id>

[LoadBalancer]
create-monitor = yes
monitor-delay = 1m
monitor-timeout = 30s
monitor-max-retries = 3

[Plugin]
plugin-name = ovs
```

Start:

```
# Start kubestack on each machine
kubestack -logtostderr=true -v=4 -group=kube
```

Configure kubernetes controller manage using openstack network provider:

```
kube-controller-manager -network-provider=openstack -...
```

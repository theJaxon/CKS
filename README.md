# CKS
![CKS](https://img.shields.io/badge/-CKS-0690FA?style=for-the-badge&logo=kubernetes&logoColor=white)
![K8s](https://img.shields.io/badge/-kubernetes-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white)

Preparation for Certified Kubernetes Security Specialist (CKS) Exam V1.19

---

#### :open_file_folder: Important Dirs:
```bash
# Inside the container 
/var/run/secrets/kubernetes.io/serviceaccount
  /token # The token from the secret that gets created with the sa is here

/proc
  /<PID>/fd # Shows files opened by this process
  /<PID>/environ # Contains environment variables

/etc
  /falco # Main config file is falco.yml
  /apparmor.d # Contains AppArmor profiles
    /abstractions # Contains templates that can be included in other apparmor profiles
    /tunables # Contains pre-defined variables (This directory can be used to either define new variables or make profile tweaks)

# APPARMOR Loaded Profiles 
/sys/kernel/security/apparmor/profiles

# SECCOMP
/var/lib/kubelet/seccomp/profiles

# Kubelet configuration 
/var/lib/kubelet/config.yaml
/etc/systemd/system/kubelet.service.d/10-kubeadm.conf # Main kubelet config file that kubeadm uses for kubeadm clusters
```

---

#### Useful commands:
```bash
# Copy the whole filesystem from a docker container to a new folder on the host 
docker cp <container-id>:/ <folder-name>

# View decoded credentials in kubeconfig file 
k config view --raw

curl https://kubernetes -k -H "Authorization: Bearer <token>"

# Force delete and create new pod using file 
k replace -f <file>.yml --force

# Inspecting certificates 
openssl x509 -in /etc/kubernetes/pki/apiserver.crt -text

# Encrypt all secrets after creating a new EncryptionConfiguration
k get secrets -A -oyaml | k replace -f - # This creates all secrets again but they get created according to the first provider defined in the EncryptionConfig file

# Crictl 
crictl pull <image-name>
crictl ps 
circtl pods 

# AppArmor 

# Load profile in enforce mode
apparmor_parser /etc/apparmor.d/<profile-name>

# Load profile in complain mode 
apparmor_parser -C /etc/apparmor.d/<profile-name>

# Check open ports
ss -tunap
lsof -i :<port-number> # lsof -i :6443

# Restart the kubelet whenever you change the config file
systemctl daemon-reload
systemctl restart kubelet.service
```

---

#### List of Open Ports on Kubeadm cluster:
##### Control Plane ports:

##### Worker nodes ports:

---

#### Important Documentation pages for CKS:
1. [Auditing](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/)
   [Log backend section](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/#log-backend)
2. [AppArmor](https://kubernetes.io/docs/tutorials/clusters/apparmor/)
3. [SeccComp](https://kubernetes.io/docs/tutorials/clusters/seccomp/)
4. [PSP](https://kubernetes.io/docs/concepts/policy/pod-security-policy/)
5. [RuntimeClass](https://kubernetes.io/docs/concepts/containers/runtime-class/)
6. [NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
7. [EncryptionConfiguration](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)

---

### List of Tools:

|           Tool           	|                                         Address                                         	|
|:------------------------:	|:---------------------------------------------------------------------------------------:	|
|        Kube-bench        	| Checks whether Kubernetes cluster is secure by verifying that it follows CIS benchmarks 	|
| Anchore, Clair and Trivy 	|                             Container vulnerability scanners                            	|
|           Falco          	|                                  runtime security tool                                  	|
|          KubeSec         	|             Statically analyze kubernetes resource definitions (YAML files)             	|

---

### :purple_circle: Cluster Setup:
#### :small_blue_diamond: 1. Network security policies to restrict cluster level access:
* Firewall rules in K8s.
* [CNI Plugin](https://itnext.io/benchmark-results-of-kubernetes-network-plugins-cni-over-10gbit-s-network-updated-august-2020-6e1b757b9e49) must support NetworkPolicies in order for them to take effect.
* Namespaced 
* Restrict ingress/egress for a set of pods based on specified rules.

---

##### Examples:

1. Deny-all policy on a specific pod
```
k run nginx --image=nginx 
k expose po nginx --port 80 --target-port 80 
k apply -f https://raw.githubusercontent.com/kubernetes/website/master/content/en/examples/admin/dns/dnsutils.yaml
k exec dnsutils -- wget -qO- nginx # Returns response showing the index page 
vi netpol.yml
```

```yml
# Deny All ingress traffic to nginx pod
apiVersion: networking.k8s.io/v1
kind: NetworkingPolicy 
metadata:
  name: deny-nginx-ingress
spec:
  podSelector:
    matchLabels:
      run: nginx 
  ingress: [] 
```
Now execting `k exec dnsutils -- wget -qO- nginx` shows no response

---

#### :small_blue_diamond: 2. Review cluster components security [etcd, kubelet, kubedns, kubeapi] using CIS benchmark:
##### Automate the process using kube-bench:
```bash
curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.3.1/kube-bench_0.3.1_linux_amd64.deb -o kube-bench_0.3.1_linux_amd64.deb
sudo apt install ./kube-bench_0.3.1_linux_amd64.deb -f

# kube-bench [master|node]

# Run kube-bench on master node 
kube-bench master

# Run kube-bench on worker node
kube-bench node
```
##### ETCD security:
1. Plain text data storage

```bash
# Store data in etcd (key is cluster and value is kubernetes)
(
ETCDCTL_API=3 etcdctl put theawesomecluster "kubernetes" \
--cacert /etc/kubernetes/pki/etcd/ca.crt \
--cert /etc/kubernetes/pki/etcd/server.crt \
--key /etc/kubernetes/pki/etcd/server.key 
)

# View the data 
(
ETCDCTL_API=3 etcdctl get cluster \
--cacert /etc/kubernetes/pki/etcd/ca.crt \
--cert /etc/kubernetes/pki/etcd/server.crt \
--key /etc/kubernetes/pki/etcd/server.key 
)

> cluster
> kubernetes

# Dump etcd 
(
ETCDCTL_API=3 etcdctl snapshot save \
--cacert /etc/kubernetes/pki/etcd/ca.crt \
--cert /etc/kubernetes/pki/etcd/server.crt \
--key /etc/kubernetes/pki/etcd/server.key \
/tmp/etcd
)

# Search etcd 
cat /tmp/etcd | strings | grep theawesome -B5 -A5
```

2. Transport security with HTTPS (in transit encryption)
- Data transferred from API server to ETCD must be encrypted

3. Client Authentication
- ETCD must enforce that only HTTPS requests with a valid client certificate that is signed by the CA is accepted
```bash
--client-cert-auth=True
--trusted-ca-file=<path-to-trusted-ca>
```

---

#### Ingress:
- Create an nginx deployment and a expose it
```bash
k create deployment nginx --image=nginx --port=80 $do > nginx.yml
k apply -f nginx.yml

k expose deploy/nginx --port=80 --target-port=80 --type=LoadBalancer $do > nginx-svc.yml
k apply -f nginx-svc.yml
```
- Generate new self signed certificate:
```bash
openssl req -x509 -newkey rsa:4096 -keyout ingress.key -nodes -subj="/CN=test.ingress.com/O=security" -days 365 -out ingress.crt
```
- Create a new TLS secret to be used with ingress:
```bash
k create secret tls test-ingress-secret --key=ingress.key --cert=ingress.crt $do > test-ingress-secret.yml
k apply -f test-ingress-secret.yml
```
- Use the TLS secret with ingress:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: tls-example-ingress
spec:
  tls:
  - hosts:
    - test.ingress.com
    secretName: test-ingress-secret
  rules:
  - host: test.ingress.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: nginx
            port:
              number: 80
```
- Modify /etc/hosts to resolve the site name
```bash
vi /etc/hosts
192.168.100.10 test.ingress.com

k get svc -n ingress-nginx 
ingress-nginx-controller             NodePort    10.101.54.114   <none>        80:30478/TCP,443:32063/TCP   104m

curl -k https://test.ingress.com:32063

# Inspect server certificate
curl -kv https://test.ingress.com:32063

* Server certificate:
*  subject: CN=test.ingress.com; O=security
*  start date: Jan 12 17:44:31 2021 GMT
*  expire date: Jan 12 17:44:31 2022 GMT

```


---

#### ServiceAccounts:

> :blue_book: 5.1.5 Ensure that default service accounts are not actively used (Manual)

- ServiceAccounts are namespaced
- `default` service account gets automatically created when a new namespace gets created
- pods are automatically mounted with `default` service account
- Disable SA token to prevent the pod from talking to the kubernetes-api
* Can be done on the level of the SA itself, in metadata section set `automountServiceAccountToken: False`
* Can be done on the pod level, in spec `automountServiceAccountToken: False`

- You can also create a new SA for each pod and specify that it should be used.
```bash
k create sa nginx 
k run nginx --image=nginx --serviceaccount=nginx 
```
- Whenever a new SA gets created, a `token` also gets generated for it 
```bash
k describe sa nginx 
# Mountable secrets: nginx-token-b4nd4
# Tokens: nginx-token-b4nd4
```

- The token is stored as a **Secret** 
```bash
k get secrets 
# nginx-token-b4nd4  kubernetes.io/service-account-token   3      105s
```
- You can use this token as an authentication bearer token `k get secret <name> -o jsonpath='{.data.token}'`


#### 5. :small_blue_diamond: Minimize access to GUI elements:
- The dashboard container should run with the following args:
```bash
--insecure-port=0 # Disable serving over HTTP
--bind-address=127.0.0.1
```

##### Configure access to the dashboard:
```bash
# 1- Create a service account in the namespace needed (Here i'm using default NS)
k create sa k8s-admin

# 2- Create a cluster role binding for allowing admin level acceess using the SA
k create clusterrolebinding k8s-admin --clusterrole=cluster-admin --serviceaccount=default:k8s-admin

# 3- Get the secret associated with the create SA
k8s_admin_secret=$(k get sa k8s-admin -ojsonpath='{.secrets[0].name}')
k get secret $k8s_admin_secret -o jsonpath='{.data.token}' | base64 -d # Use the token to login to the dashboard

k port-forward svc/kubernetes-dashboard -n kubernetes-dashboard 8888:443 --address 0.0.0.0
```

---
---

### :purple_circle: Cluster Hardening:
#### :small_blue_diamond: 1. Restrict access to kubernetes API:
What happens when a request gets sent to the kuberntes API?
When a request is sent to the kubernetes API it goes through 3 levels of checks:
* Authentication check (Who is the one making the request)
* Authorization check (Are you allowed to perform the action)
* Admission control check (ex: can new pods be created or we reached a max, in this case even if you can do the action of creating pods you'll be denied by the admission controller)

API requests are tied to:
* Normal user
* Service account 
* Anonymous request (If the request didn't authenticate)

Default ClusterRole objects and their capabilities `k get clusterrole`: 

| ClusterRole      | Description |
| ----------- | ----------- |
| cluster-admin      | Allows performing any desired action on resources       |
| admin   | Allows admin access, granted within a namespace using a RoleBinding        |
| edit   | Allows RW access to most objects in a namespace        |
| view   | Allows RO access to most objects in a namespace         |

To restrict API access you should:
1. Block anonymous access
2. Close insecure port 
3. Don't expose kube-apiserver to the outside
4. Restrict access from nodes to API **NodeRestriction**
5. Prevent unauthorized access using RBAC
6. Prevent pods from accessing API `automountServiceAccountToken: False`

##### 1.Block anonymous access:
> :blue_book: 1.2.1 Ensure that the **--anonymous-auth** argument is set to **false** (Manual) 

* In `/etc/kubernetes/manifests/kube-apiserver.yaml` the **--anonymous-auth** flag can be set to true or false.
* Anonymous access is enabled by default.
* RBAC requires explicit authorization for anonymous access.
* For applying RBAC resources (Roles, RoleBindings, ClusterRoles and ClusterRoleBindings) its preffered if the used command is `k auth reconcile -f name.yaml`

Testing if the API server accepts anonymous requests:
```bash
curl https://localhost:6443 -k 
# "message": "forbidden: User \"system:anonymous\" cannot get path \"/\""
```

Testing again after setting `--anonymous-auth=False`:
```bash
curl https://localhost:6443 -k
# "message": "Unauthorized"
```

##### 2.Close insecure port:
> :blue_book: 1.2.19 Ensure that the **--insecure-port** argument is set to **0** (Automated)

* `--insecure-port` can be configured to allow HTTP requests to the API 
* Request sent over the insecure port **bypassess** authentication and authorization.
* The insecure port shouldn't be allowed, it's helpful only for debugging purposes.

```bash
vi /etc/kubernetes/manifests/kube-apiserver.yaml
--insecure-port=8888
curl localhost:8888 # Shows all API endpoints, no need for authentication nor authorization
```
* Disable the insecure port by setting it to zero `--insecure-port=0`

##### 3.Don't expose kube-apiserver to the outside:
Make the api-server accessible externally by modifying the `kubernetes` svc and changing its type to `NodePort`
```bash
k edit svc kubernetes
type: NodePort
```
* From a different machine curl the <node-ip>:<k8s-svc-port> and it works
* curl with -k to authenticate as anonymous user
* Copy the kubeconfig file on the host `scp <user>@<ip>:/home/<user>/.kube/conf .`
* Access externally using kubectl as `kubectl --kubeconfig conf get po`

##### 4.Restrict access from nodes to API using NodeRestriction admission controller:
* Enable NodeRestriction using `--enable-admission-plugins=NodeRestriction`
* Limits node labels that can be modified by the kubelet
* This ensures secure workload via labels
* For worker nodes the config file is located at `/etc/kubernetes/kubelet.conf`
```bash
kubectl --kubeconfig /etc/kubernetes/kubelet.conf get ns 
# Error from server (Forbidden): namespaces is forbidden: User "system:node:worker1" cannot list resource "namespaces" in API group "" at the cluster scope
kubectl --kubeconfig /etc/kubernetes/kubelet.conf get node # Works 

# Try to label Master node 
sudo kubectl label node master node=master --kubeconfig /etc/kubernetes/kubelet.conf
# Error from server (Forbidden): nodes "master" is forbidden: node "worker1" is not allowed to modify node "master"

# This works when modifying our own node label
sudo kubectl label node worker1 node=worker1 --kubeconfig /etc/kubernetes/kubelet.conf
#node/worker1 labeled
```
* Node restriction also prevents setting a label starting with `node-restriction.kubernetes.io`

##### Connecting to the API server manually with certificates:
* `k config view --raw` shows the certificates encoded in the config file .. 3 files will be extracted from the config file in order to manually connect to the server 
1. certificate-authority
2. client-certificate
3. client-key

Decode them, store them in files as they will be used with the curl command to talk to the API server
```bash
curl https://<server>:6443 # Request fails
curl https://<server>:6443 --cacert ca.crt --cert client.crt --key client.key 
```

---

#### Helpful tips from CIS benchmarks to secure API server:
> :blue_book: 1.2.1 Ensure that the --anonymous-auth argument is set to false (Manual)

```bash
vi /etc/kubernetes/manifests/kube-apiserver.yaml
--anonymous-auth=False
```

> :blue_book: 1.2.2 Ensure that the --basic-auth-file argument is not set (Automated)

> :blue_book: 1.2.3 Ensure that the --token-auth-file parameter is not set (Automated)

```bash
# Comment out the argument
--basic-auth-file
--token-auth-file
```

> :blue_book: 1.2.4 Ensure that the --kubelet-https argument is set to true (Automated)

```bash
--kubelet-https=True
```

> 1.2.12 Ensure that the admission control plugin AlwaysPullImages is set (Manual)

```bash
--enable-admission-plugins=...,AlwaysPullImages,...
```

---
---

### :purple_circle: System Hardening:
#### :small_blue_diamond: 1. Use kernel hardening tools [AppArmor, seccomp]:
- Containerized app process can communicate with Syscall interface which passes the request to the linux kernel, this needs to be restricted
- Seccomp or AppArmor will be an additional layer above the Syscall interface 
- Docker has builtin [Seccomp Filter that is used by default](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) 

![AppArmor](https://github.com/theJaxon/CKS/blob/main/etc/System%20Hardening/Diagram1.png)

##### AppArmor:
- Any application can access system functionality like Filesystem, other processes or Network interfaces.
- With AppArmor a shield is created between our processes and these functionalities, we control what's allowed or disallowed
- This is done by creating a `Profile` for the app (ex: new profile will be created for firefox)
- The profile must be loaded into the Kernel (Can be verified by checking `/sys/kernel/security/apparmor/profiles`)
- Same can be done for Kubernetes components (ex: a profile for the Kubelet)
- There are 3 AppArmor profile modes available:
  1. Unconfined # Nothing is enforced (Similar to **Disabled** in SELinux)
  2. Complain # Processes can escape but it will be logged (Similar to **permissive** mode in SELinux)
  3. Enforce # Processes are under control (Similar to .. **Enforcing** in SELinux ..)

```bash
# Check apparmor service status
systemctl status apparmor.service

apt-get install apparmor-utils \
                apparmor-profiles \ 
                apparmor-profiles-extra -y
```

Basic AppArmor commands:
```bash
# Show all profiles
aa-status

# Generate new profile for an application
aa-genprof

# Put profile in complain mode
aa-complain

# Same as enforce mode except that allowed actions get logged in addition to the actions that were blocked
aa-audit

# Put profile in enforce mode (only blocked actions gets logged)
aa-enforce

# Update the profile if app produced more usage logs
aa-logprof

# Disable the profile completely
aa-disable
```

##### Setup simple AppArmor for curl:
```bash
# Testing curl before applying AppArmor profile 
curl -v google.com

TCP_NODELAY set
* Connected to google.com

# Generate a new profile 
aa-genprof curl

curl -v google.com
* Could not resolve host: google.com
* Closing connection 0
curl: (6) Could not resolve host: google.com

# Check the profile 
cd /etc/apparmor.d/<usr.bin.curl> # The profile is named based on the absolute path for the binary

# Update profile according to the logs
aa-logprof 

# If you curl google.com again the results are back as they were the first time
```

##### AppArmor profile for Nginx docker container:
From the documentation there's an AppArmor profile that denies all file writes:
```bash
vi /etc/apparmor.d/deny-all-writes

#include <tunables/global>

profile deny-all-writes flags=(attach_disconnected) {
  #include <abstractions/base>

  file,

  # Deny all file writes.
  deny /** w,
}

# Apply the profile using apparmor_parser
apparmor_parser /etc/apparmor.d/deny-all-writes

# Verify that profile is now loaded
aa-status | grep deny-all
```

Test AppArmor docker-default profile with ngninx container
```bash
docker run --security-opt apparmor=docker-default nginx

# Result 
/docker-entrypoint.sh: /docker-entrypoint.d/ is not empty, will attempt to perform configuration
/docker-entrypoint.sh: Looking for shell scripts in /docker-entrypoint.d/
/docker-entrypoint.sh: Launching /docker-entrypoint.d/10-listen-on-ipv6-by-default.sh
10-listen-on-ipv6-by-default.sh: info: Getting the checksum of /etc/nginx/conf.d/default.conf
10-listen-on-ipv6-by-default.sh: info: Enabled listen on IPv6 in /etc/nginx/conf.d/default.conf
/docker-entrypoint.sh: Launching /docker-entrypoint.d/20-envsubst-on-templates.sh
/docker-entrypoint.sh: Configuration complete; ready for start up
```

Test AppArmor deny-all-writes profile with the same container
```bash
docker run --security-opt apparmor=deny-all-writes nginx

# Result: The container failed to start 
/docker-entrypoint.sh: No files found in /docker-entrypoint.d/, skipping configuration
/docker-entrypoint.sh: 13: /docker-entrypoint.sh: cannot create /dev/null: Permission denied
2021/01/07 11:53:16 [emerg] 1#1: mkdir() "/var/cache/nginx/client_temp" failed (13: Permission denied)
nginx: [emerg] mkdir() "/var/cache/nginx/client_temp" failed (13: Permission denied)
```

##### [AppArmor with Kubernetes](https://kubernetes.io/docs/tutorials/clusters/apparmor/#securing-a-pod):
- Container runtime must support AppArmor in order for it to work
- AppArmor should be installed on the nodes where the pod will be scheduled on
- AppArmor profile must be available on nodes where AppArmor is installed
- AppArmor profiles are specified per **Container** not per ~~pod~~
- In annotations the container and profile are specified as `container.apparmor.security.beta.kubernetes.io/<container_name>: <profile>`

![AppArmor](https://github.com/theJaxon/CKS/blob/main/etc/AppArmor/AppArmor.png)

1. Create a new profile in `/etc/apparmor.d/<profile> and add load it
```bash
vi /etc/apparmor.d/k8s-deny-all-writes
apparmor_parser /etc/apparmor.d/k8s-deny-all-writes

# Check the profile 
aa-status | grep k8s
>  k8s-deny-all-writes
```

2. Run the container with the added AppArmor annotation
```yaml
k run app-armor-test --image=nginx $do > nginx.yml
vi nginx.yml

metadata:
  annotations:
    container.apparmor.security.beta.kubernetes.io/app-armor-test: localhost/k8s-deny-all-writes
```

##### Seccomp:
- "Secure Computing mode" is a security facility in the linux kernel
- Restricts execution of Syscalls made by processes
- Seccomp works for the whole pod
- There are 2 modes for seccomp:
  1. Strict mode
  2. Filter mode

```bash
# Check if seccomp is available on the system 
grep SECCOMP /boot/config-$(uname -r)
> CONFIG_SECCOMP=y
> CONFIG_HAVE_ARCH_SECCOMP_FILTER=y
> CONFIG_SECCOMP_FILTER=y
```

```yaml
# On worker node
mkdir -pv /var/lib/kubelet/seccomp/profiles
mv audit.json /var/lib/kubelet/seccomp/profiles/

# Create a pod that uses seccomp profile
apiVersion: v1
kind: Pod
metadata:
  name: audit-pod
  labels:
    run: audit-pod
spec:
  nodeName: worker1
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/audit.json
  containers:
  - name: audit-container
    image: hashicorp/http-echo:0.2.3
    args:
    - "-text=just made some syscalls!"
    securityContext:
      allowPrivilegeEscalation: false
```

Further validating that things worked correctly
```bash
# easy way
k describe po <name> # 
> Annotations:  seccomp.security.alpha.kubernetes.io/pod: localhost/profiles/audit.json

# Different approach 
ssh <node-where-seccomp-po-runs>
ps aux | grep <name> # Here i grep on nginx as i'm running nginx pod .. get the process ID
grep -i seccomp /proc/<PID>/status
> Seccomp:        2
```

---

#### :small_blue_diamond: 2. Minimize host OS footprint (reduce attack surface):
- Disable snapd 
```bash
systemctl mask snapd # Or you can just systemctl disable snapd, masking is just so that nobody systemctl start snapd 
```

Find and disable the app listening on port 21:
```bash
lsof -i :21 # VSFTPD
systemctl disable vsftpd
```

---
---

### :purple_circle: Minimize Microservice Vulnerabilities:
#### :small_blue_diamond: 1. Setup appropriate OS level security domains [PSP, OPA, security contexts]:

Security context:
- Used to define privilege and access control.
- Can be defined at pod level (applies to all containers) or at a container level

<details>
<summary>SecurityContext at Pod level</summary>
<p>

```bash
k explain pod.spec.securityContext --recursive
fsGroup      <integer>
fsGroupChangePolicy  <string>
runAsGroup   <integer>
runAsNonRoot <boolean>
runAsUser    <integer>
seLinuxOptions       <Object>
seccompProfile       <Object>
supplementalGroups   <[]integer>
sysctls      <[]Object>
```

</p>
</details>

<details>
<summary>SecurityContext at container level</summary>
<p>

```bash
k explain pod.spec.containers.securityContext --recursive
allowPrivilegeEscalation     <boolean>
capabilities <Object>
privileged   <boolean>
procMount    <string>
readOnlyRootFilesystem       <boolean>
runAsGroup   <integer>
runAsNonRoot <boolean>
runAsUser    <integer>
seLinuxOptions       <Object>
seccompProfile       <Object>
```

</p>
</details>

##### Privileged containers:
- By default docker containers run unprivileged, although they're running as root but they're actually giving just a portion of the capabilites.
- Privileged containers are given all the `Capabilities` which is very dangerous.
- To allow container to become a privileged one use `privileged: True` security context.

Example - Changing hostname inside the container:
```bash
k run alpine --image=alpine --command sleep 3600 
k exec -it alpine -- sh
apk add strace libcap
strace hostname jaxon
# write(2, "hostname: sethostname: Operation"..., 47hostname: sethostname: Operation not permitted
# View capabilites for this container in unprivileged mode
capsh --print 
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+eip
```
The container needs sethostname which exists in `CAP_SYS_ADMIN` , now setting `privileged: True` will add this capability (in addition to the rest of them)
```yaml
spec:
  containers:
  - command:
    - sleep
    - "3600"
    image: alpine
    name: alpine
    securityContext:
      privileged: True
```
```bash
k replace -f alpine.yml --force 
vagrant@master:~$ k exec -it alpine -- sh
/# hostname
alpine
/# hostname jaxon
/# hostname
jaxon # Success

# View list of capabilities for this container
apk add libcap

/# capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+eip
```

##### [Privilege escalation](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#privilege-escalation):
- Privilege escalation controls whether a process can gain more privileges than its partent process
- By default k8s allows privilege escalation so you should set `allowPrivilegeEscalation: False` at the container level

```yaml
spec:
  containers:
  - command:
    - sleep
    - "3600"
    image: alpine
    name: alpine
    securityContext:
      allowPrivilegeEscalation: True 
```
```bash
# Check privilege escalation flag
k exec alpine -- cat /proc/1/status
NoNewPrivs:     0 # Allow privilege escalation

vi alpine.yml
allowPrivilegeEscalation: False 
k replace -f alpine.yml --force
k exec alpine -- cat /proc/1/status
NoNewPrivs:     1 # Disable privilege escalation
```

##### [Pod security policy](https://kubernetes.io/docs/concepts/policy/pod-security-policy/):
> :blue_book: 1.2.16 Ensure that the admission control plugin PodSecurityPolicy is set (Automated)

- Pod security policy is an admission controller which controls under which security conditions a pod has to run
- Can be enabled by modifying kube-apiserver manifest `--enable-admission-plugins=PodSecurityPolicy`
- PodSecurityPolicy or OPA can be used to enhance security by enforcing that only specific container registries are allowed.
- It's recommended that policies are added and authorized first before enabling PSP admission controller.
- When PSP is allowed, static pods in the `kube-system` namespace will fail to get created by the kubelet, to solve this a permissive PSP needs to be created and associated with the all the authenticated users by using `system:authenticated` group.

###### Permissive PSP to allow pods in kube-system namespace to work:
```bash
# Create the PSP before enabling pod security policy 
k apply -f permissive-psp.yml

k create clusterrole permissive --verb=use --resource=psp --resource-name=permissive $do > permissive-clusterrole.yml
k apply -f permissive-clusterrole.yml

# Allow the permissive role only to work in the kube-system namespace
k create rolebinding permissive --clusterrole=permissive --group=system:authenticated -n kube-system $do > permissive-rolebinding.yml
k apply -f permissive-rolebinding.yml

# Modify kube-apiserver manifest 
vi /etc/kubernetes/manifests/kube-apiserver.yaml 
- --enable-admission-plugins=NodeRestriction,PodSecurityPolicy

k get events -n kube-system --sort-by=metadata.creationTimestamp
```

###### PodSecurityPolicy Workflow:

![PSP-Workflow](https://github.com/theJaxon/CKS/blob/main/etc/PSP/PSP-Workflow.png)

1. Create and use a PSP 
```yaml
# Nginx will fail if it can't create new files
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: block-nginx
spec:
  readOnlyRootFilesystem: True
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  volumes:
  - '*'

k apply -f block-nginx-psp.yml
```

2. Create a Role or a ClusterRole that uses the PSP
```bash
k create role block-nginx --verb=use --resource=psp --resource-name=block-nginx $do > block-nginx-role.yml 
k apply -f block-nginx-role.yml
```

3. Create a RoleBinding or a ClusterRoleBinding that binds the role created to either a SA, a user or a group
```bash
# Create a service account 
k create sa nginx $do > nginx-sa.yml
k apply -f nginx-sa.yml

# Bind the SA to the created role in a rolebinding
k create rolebinding block-nginx --role=block-nginx --serviceaccount=default:nginx $do > block-nginx-rolebinding.yml
k apply -f block-nginx-rolebinding.yml
```

Test by creating an nginx deployment and checking the logs
```yaml
k create deploy nginx --image=nginx $do > nginx-deploy.yml

# Modify it to use the nginx sa instead of the default 
vi nginx-deploy.yml
spec:
  serviceAccountName: nginx
  containers:
  - image: nginx
    name: nginx

# Check if pods were created 
k get po
NAME                     READY   STATUS   RESTARTS   AGE
nginx-694c9fb47d-xjd5d   0/1     Error    2          39s

# Check the events
k get events --sort-by=metadata.creationTimestamp

# Check the logs 
k logs k logs nginx-694c9fb47d-xjd5d   
> 2021/01/13 16:17:00 [emerg] 1#1: mkdir() "/var/cache/nginx/client_temp" failed (30: Read-only file system)
> nginx: [emerg] mkdir() "/var/cache/nginx/client_temp" failed (30: Read-only file system)
```

```yaml
spec:
  privileged: False
  allowPrivilegeEscalation: False 
  # The rest fills in some required fields.
```
- This ensures that privileged pods or those who allow privilege escalation will not be created.
- The default service account need to be modified so that the newly created deployment work with the PodSecurityPolicy
 
```bash
k create role psp-access --verb=use --resource=psp
k create rolebinding psp-access --role=psp-access --serviceaccount=default:default
```

###### Issues regarding hostPath Volumes:
- hostPath volumes allows us to mount a file or directory from the hosts node FS into the pod
- The path can be `/` which mounts the whole root of the host into the pod
- To mitigate this `hostPath` type shouldn't be allowed and this could be done through PSP

```bash
k apply -f restrictive-psp.yml

k create clusterrole restrictive --verb=use --resource=psp --resource-name=restricted $do > restrictive-clusterrole.yml
k apply -f restrictive-clusterrole.yml

k create rolebinding restrictive --clusterrole=restrictive --group=system:authenticated -n default $do > restrictive-rolebinding.yml
k apply -f restrictive-rolebinding.yml
```

##### [Open Policy Agent](https://github.com/open-policy-agent/opa) [OPA]:
- A general-purpose policy engine that enables unified, context-aware policy enforcement across the entire stack.
- OPA [Gatekeeper](https://github.com/open-policy-agent/gatekeeper) makes OPA easier to use with kubernetes through the creation of CRDs
- OPA Gatekeeper consists mainly of 3 parts:
  1. A webhook server and a generic ValidatingWebhookConfiguration
  2. [`ConstraintTemplate`](https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/#policies-and-constraints) which describes the admission control policy
  3. `Constraint` that gets created based on the previous ConstraintTemplate

Install OPA gatekeeper:
```bash
k apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.1/deploy/gatekeeper.yaml

# List the newly creatd CRDs
k get crd
NAME                                                
configs.config.gatekeeper.sh                         
constraintpodstatuses.status.gatekeeper.sh           
constrainttemplatepodstatuses.status.gatekeeper.sh  
constrainttemplates.templates.gatekeeper.sh   
```

Constraint template example:
```yaml
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabel 
```
- This constraint template generates a CRD of type k8srequiredlabel which can be used as a `kind` in `Constraint`

##### Admission Webhooks:
- Admission webhooks are more like admission controllers, there are 2 types of them
1. [Validating admission webhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#validatingadmissionwebhook)
2. Mutating admission webhook
- When you create a new object it needs to pass through these webhooks
- A validating admission webhook just validates the pod definition (either approves or denies it)
- A mutating admission webhook modifies the pod definition
- OPA workes with **validating admission webhook**

---

#### :small_blue_diamond: 2. Manage kubernetes secrets
* Get a secret from ETCD 
```bash
k create secret generic s1 --from-literal=user=admin

ETCDCTL_API=3 etcdctl get /registry/secrets/<namespace>/<secret-name> \ 
--cacert /etc/kubernetes/pki/etcd/ca.crt \
--cert /etc/kubernetes/pki/etcd/server.crt \
--key /etc/kubernetes/pki/etcd/server.key 
```

<details>
<summary>Output</summary>
<p>

```
/registry/secrets/default/s1
k8s


v1Secret

s1default"*$55889b6d-02cc-4e3c-b872-74fe658299312ݭz_
kubectl-createUpdatevݭFieldsV1:-
+{"f:data":{".":{},"f:user":{}},"f:type":{}}
useradminOpaque"
```

</p>
</details>

* Encrypting ETCD and secrets inside it:
- This is done by creating an [**`EncryptionConfiguration`**](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/) object and passing this object to the API server `--encryption-provider-config` which is the component responsible for communicating with ETCD.
- The main disadvantage of this approach is that it relies on the key being stored on the host OS, so while this protects against etcd compromise, it doesn't protect against the host OS compromise.


How EncryptionConfiguration works?
- Under `resources` we specify the resources to be encrypted
- Under [`providers`](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/#providers) section we specify an array of providers:
  - `identity` provider is the default and it doesn't encrypt anything.
  - `aesgcm` | `aescbc` and those are 2 encryption algorithms that can be used
- The provider section works in order so the first provider defined is used for **encryption on save**

Example 1:
```yaml
providers:
- identity: {} # Store secrets UNENCRYPTED
- aesgcm:
    keys:
    - name: key1
      secret: base64-encoded-text
- aescbc:
    keys:
    - name: key2
      secret: base64-encoded-text
```
When reading secrets using the previous example they can be read as either 
- unencrypted 
- aesgcm encrypted
- aescbc encrypted

---

Example 2:
```yaml
providers:
- aesgcm: # All new secrets will be stored ENCRYPTED
    keys:
    - name: key1
      secret: base64
    - name: key2
      secret: base64
- identity: {} 
```
Secrets can be read as either
- Encrypted aesgcm
- Unencrypted

---

Apply an EncryptionConfiguration file:
```yaml
echo random-password | base64 # cmFuZG9tLXBhc3N3b3JkCg== will be the value of the aescbc secret
mkdir -p /etc/kubernetes/etcd
vi /etc/kubernetes/etcd/ec.yml

apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
    - secrets
    providers:
    - aescbc:
        keys:
        - name: key1
          secret: cmFuZG9tLXBhc3N3b3JkCg==
    - identity: {}

# Refernce this file in the api-server
sudo vi /etc/kubernetes/manifests/kube-apiserver.yaml
--encryption-provider-config=/etc/kubernetes/etcd/ec.yml

# Add volume 
volumes:
- name: etcd-v 
  hostPath:
    path: /etc/kubernetes/etcd
    type: DirectoryOrCreate

# Mount the vol in the container 
volumeMounts:
- name: etcd-v 
  mountPath: /etc/kubernetes/etcd
  readOny: True 
```

Test if things worked as expected:
```bash
k create secret generic j1 --from-literal=user=admin
sudo ETCDCTL_API=3 etcdctl get /registry/secrets/default/j1 
--cacert /etc/kubernetes/pki/etcd/ca.crt 
--cert /etc/kubernetes/pki/etcd/server.crt 
--key /etc/kubernetes/pki/etcd/server.key  # Shows gibberish text so our secret is now encrypted in ETCD
```

Encrypt all secrets that existed
```
k get secret -A -oyaml | k replace -f -
```

---

#### :small_blue_diamond: 3. Use container runtime sandboxes in multi-tenant environments [gvisor, kata containers]:
* A sandbox is an additional security layer to reduce the attack surface
Introducing sandboxes adds another defense layer but it comes with its costs too
- More resources are needed
- Not good for syscall heavy workloads
- A `RuntimeClass` is a non-namespaced resource, it's a feature for selecting container runtime configuration

##### [Kata Containers](https://github.com/kata-containers/kata-containers):
- Runs containers inside a lightweight VM thus providing a strong separation layer

##### [gVisor](https://github.com/google/gvisor):
- A kernel that runs in user-space.
- Not VM based 
- Simulates kernel syscalls with limited functionality
- Runtime is called `runsc`

![gVisor](https://github.com/theJaxon/CKS/blob/main/etc/gVisor/gVisor.png)

Install gVisor/runsc with containerd:
```bash
sudo apt-get update && sudo apt-get install -y apt-transport-https ca-certificates curl gnupg-agent software-properties-common

# Configure keys
curl -fsSL https://gvisor.dev/archive.key | sudo apt-key add -
sudo add-apt-repository "deb https://storage.googleapis.com/gvisor/releases release main"

# Install runsc, gvisor-containerd-shim and containerd-shim-runsc-v1 binaries
sudo apt-get update && sudo apt-get install -y runsc

# Modify config.toml file to enable runsc in containerd
vi /etc/containerd/config.toml
```

```toml
disabled_plugins = ["restart"]
[plugins.linux]
  shim_debug = true
[plugins.cri.containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
```

```bash
# Use containerd by default in crictl
vi /etc/crictl.yaml
runtime-endpoint: unix:///run/containerd/containerd.sock
sudo systemctl restart containerd

# Make kubelet use containerd
vi /etc/default/kubelet
KUBELET_EXTRA_ARGS="--container-runtime remote --container-runtime-endpoint unix:///run/containerd/containerd.sock"
sudo systemctl daemon-reload
sudo systemctl restart kubelet
```

Confirm that container runtime was successfully changed for worker2:
```bash
vagrant@master:~$ k get nodes -o wide
NAME      STATUS   ROLES    AGE     VERSION   INTERNAL-IP      EXTERNAL-IP   OS-IMAGE             KERNEL-VERSION     CONTAINER-RUNTIME
master    Ready    master   7d11h   v1.20.1   192.168.100.10   <none>        Ubuntu 20.04.1 LTS   5.4.0-42-generic   docker://19.3.8
worker1   Ready    <none>   7d10h   v1.20.1   192.168.100.11   <none>        Ubuntu 20.04.1 LTS   5.4.0-42-generic   docker://19.3.8
worker2   Ready    <none>   7d10h   v1.20.1   192.168.100.12   <none>        Ubuntu 20.04.1 LTS   5.4.0-42-generic   containerd://1.3.3-0ubuntu2
```

Create a [runtime class](https://kubernetes.io/docs/concepts/containers/runtime-class/) for `runsc` (gVisor) runtime:
- The runtime class allows us to specify a different runtime handler 
- You can then specify that some pods use this specific runtime class

![gVisor-k8s](https://github.com/theJaxon/CKS/blob/main/etc/gVisor/gvisor-k8s.png)

```yaml
apiVersion: node.k8s.io/v1beta1  
kind: RuntimeClass
metadata:
  name: gvisor 
handler: runsc 
```
Test the runtime class
```bash
# Create nginx pod 
k run gvisor --image=nginx $do > gvisor-po.yml 
vi gvisor-po.yml
```

```yaml
spec:
  runtimeClassName: gvisor
  containers:
  - image: nginx
    name: gvisor
```

---

#### :small_blue_diamond: 4. Implement pod to pod encryption by use of mTLS:
- mTLS stands for Mutual TLS
- Two-way authentication (the 2 parties are authenticating each other at the same time)
- Service Mesh manages the whole process (Istio or linkerd) are deployed as side cars.

##### :car: Create proxy sidecar:

```bash
k run main-container --image=bash $do > main-container.yml --command ping google.com
k apply -f main-container.yml
vi main-container.yml 
```

```yaml
# Additional side car container that uses iptables and thus needs NET_ADMIN capability
- name: proxy 
  image: ubuntu
  command: 
  - sh
  - -c
  - 'apt-get update && apt-get install iptables -y && iptables -L && sleep 1d'
  securityContext:
    capabilites:
      add:
      - NET_ADMIN
```

---
---

### :purple_circle: Supply Chain Security:
#### :small_blue_diamond: 1. Minimize base image footprint:
- Only instructions `RUN` `COPY` and `ADD` create layers, other instructions create temporary intermediate images and don't increase build size.
- Image footprint can be reduced using **Multi stage builds**

##### Secure and harden the image:
1. Use specific base image version instead of ~~latest~~
2. Don't run as USER ~~root~~
3. Make Filesystem `ReadOnly` `pod.spec.containers.securityContext.readOnlyRootFilesystem` 
4. Remove Shell access `RUN rm -rf /bin/bash /bin/sh`

---

#### :small_blue_diamond: 2. Secure your supply chain: whitelist allowed image registries, sign and validate images:
##### Private registries with Kubernetes:
- A secret of type [`docker-registry`](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/#create-a-pod-that-uses-your-secret) is created that contains the login details for the private registry.
- The secret is then refernced using `pod.spec.containers.imagePullSecrets`
- Another approach is to add the secret to the ServiceAccount of the container `k patch sa default -p '{"imagePullSecrets": [{"name": "secret-name"}]}' 

##### List all registries used in the cluster:
```bash
k get po -A -oyaml | grep "image:" | grep -v "f:" # -v is invert match means it grep all lines that doesn't match this one
```

##### Use image digest instead of version for kube-apiserver:
- The problem with using image tags is that the image itself might be changed, a tag like image:18 doesn't truely ensure that the same image will be used each and every time, only a digest ensures this since there can only be a unique digest (read more in the article [Docker Tag vs Hash: A Lesson in Deterministic Ops](https://medium.com/@tariq.m.islam/container-deployments-a-lesson-in-deterministic-ops-a4a467b14a03))
```bash
k get po -n kube-system -l component=kube-apiserver -o yaml | grep imageID
# imageID: docker-pullable://k8s.gcr.io/kube-apiserver@sha256:6ea8c40355df6c6c47050448e1f88cb4a5d618e9e96717818d4e11fcfe156ee0
sudo vi /etc/kubernetes/manifests/kube-apiserver.yaml
# Replace image with k8s.gcr.io/kube-apiserver@sha256:6ea8c40355df6c6c47050448e1f88cb4a5d618e9e96717818d4e11fcfe156ee0
```

##### Whitelist some registries with OPA:
Allow only images from docker.io and k8s.gcr.io to be used

<details>
<summary>ConstraintTemplate</summary>
<p>

```yaml
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: whitelistregistries
spec:
  crd:
    spec:
      names:
        kind: WhitelistRegistries
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package whitelistregistries
        
        violation[{"msg": msg}] {
          image := input.review.object.spec.containers[_].image 
          not startswith(image, "docker.io/")
          not startswith(image, "k8s.gcr.io/")
          msg := "This image isn't trusted !"
        }
```

</p>
</details>

<details>
<summary>Constraint</summary>
<p>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: WhitelistRegistries
metadata:
  name: whitelist-registries
spec:
  match:
    kinds:
      - apiGroups: ["*"]
        kinds: ["Pod"]
```

</p>
</details>

```bash
# Test the policy 
k run node-exporter --image=quay.io/prometheus/node-exporter
# Error from server ([denied by whitelist-registries] This image isn't trusted !): admission webhook "validation.gatekeeper.sh" denied the request: [denied by whitelist-registries] This image isn't trusted !
```

##### [ImagePolicyWebhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#imagepolicywebhook):
- If `ImagePolicyWebhook` admission controller is enabled then the request goes through it, if `ImageReview` succeeds from the external service then the request succeeds.

![ImagePolicyWebhook](https://github.com/theJaxon/CKS/blob/main/etc/ImagePolicyWebhook/image-policy-webhook.png)

##### Custom webhook kubeconfig file:
```yaml
vi /etc/kubernetes/imagePolicy/image-policy.kubeconfig

apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: /etc/kubernetes/imagePolicy/webhook.crt
    server: https://bouncer.local.lan:1323/image_policy
  name: bouncer_webhook
contexts:
- context:
    cluster: bouncer_webhook
    user: api-server
  name: bouncer_validator
current-context: bouncer_validator
preferences: {}
users:
- name: api-server
  user:
    client-certificate: /etc/kubernetes/imagePolicy/api-user.crt
    client-key: /etc/kubernetes/imagePolicy/api-user.key
```

##### Create AdmissionConfiguration

```yaml
vi /etc/kubernetes/imagePolicy/admission-config.yml

apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
- name: ImagePolicyWebhook
  configuration:
    imagePolicy:
      kubeConfigFile: /etc/kubernetes/imagePolicy/image-policy.kubeconfig
      allowTTL: 50
      denyTTL: 50 
      retryBackoff: 500
      defaultAllow: False # Deny all pod creation if external server wasn't available
```

##### Modify kube-apiserver configuration to enable ImagePolicyWebhook:
```bash
# Enable ImagePolicyWebhook
sudo vi /etc/kubernetes/manifests/kube-apiserver.yaml
- --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook
- --admission-control-config-file=/etc/kubernetes/admission/admission-config.yml

# Mount the directory 
volumes:
- name: image-policy-v 
  hostPath:
    path: /etc/kubernetes/imagePolicy 

volumeMounts:
- name: image-policy-v
  mountPath: /etc/kubernetes/imagePolicy
```

```bash
# Run kube-image-bouncer
kube-image-bouncer --cert webhook.crt --key webhook.key &
```

#### :small_blue_diamond: 3. Static analysis (Linting) of user workloads [K8s resources, Dockerfiles]:
- Checks the source code and text files against specific rules in order to enforce these rules.
- Static analysis rules examples:
  - Always define resource requests and limits 
  - Pods should never use the default Service account.
- [Kubesec](https://github.com/controlplaneio/kubesec) can do the security risk analysis for the kubernetes resources `kubesec scan <file>.yml`
- [Conftest](https://github.com/open-policy-agent/conftest) is used to write tests that can be used against the yaml definitions and Dockerfiles

---

#### :small_blue_diamond: 4. Scan images for known vulnerabilities:
- The base image may contain vulnerabilities or the software installed on top of it in another layer might container a vulnerability.
- There exists databases (ex: [CVE](https://cve.mitre.org/), [NVD](https://nvd.nist.gov/)) for known vulnerabilites and these DBs are used by tools to scan for already known vulnerabilites.
- [Clair](https://github.com/quay/clair) or [Trivy](https://github.com/aquasecurity/trivy) can be used to do vulnerability scanning (This is also considered static analysis)

##### [Install trivy](https://github.com/aquasecurity/trivy#debianubuntu):
```bash
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" > /etc/apt/sources.list.d/trivy.list
apt-get update && apt-get install trivy

trivy image <name>
```

##### Use [anchore-cli](https://github.com/anchore/anchore-cli#command-line-examples) to scan images for known vulnerabilities:
```bash
anchore-cli image add docker.io/library/debian:latest # Add image to anchore engine
anchore-cli image wait docker.io/library/debian:latest # Wait for analysis to finish
anchore-cli image list # List images already analyzed by anchore engine 
anchore-cli image get docker.io/library/debian:latest # Get summary info about the analyzed image
anchore-cli image vuln docker.io/library/debian:latest os # Perform vulnerability scan on the image
```

---
---

### :purple_circle: Monitoring, Logging and Runtime Security:
#### :small_blue_diamond: 1. Perform behavioral analytics of syscall process and file activities at the host and container level to detect malicious activities:
##### Strace:
- A tool that intercepts and logs syscalls made by a process which is helpful for diagnostics and debugging
- It can log and display signals received by a process
```bash
strace <linux-command>
strace ls -lah
strace -cw ls -lah # -cw is used to summarize the output

# Using strace with etcd
ps aux | grep etcd # check the process number
sudo strace -p <PID> -f -cw

cd /proc/<PID> && ls -lah
sudo ls -lah exe # lrwxrwxrwx 1 root root 0 Jan  5 13:58 exe -> /usr/local/bin/etcd

# Check open files by etcd
cd fd && ls -lah #  /var/lib/etcd/member/snap/db <file 7>
tail 7

# Test creating a secret and reading it from the file
k create secret generic password --from-literal pass=securepasswd
cat 7 | strings | grep securepasswd -A10 -B10 # Stored at "/registry/secrets/default/password 
```

##### /proc directory:
- Contains information and connections to processes and kernel
- /proc/<pid>/environ # Contains environment variables in use for the container

##### [Falco](https://github.com/falcosecurity/falco) by Sysdig:
- Falco rules are written in YAML, and have a variety of required and optional keys.

|    Name   |                       Purpose                      |
|:---------:|:--------------------------------------------------:|
|    rule   |                  Name of the rule                  |
|    desc   |    Description of what the rule is filtering for   |
| condition |  The logic statement that triggers a notification  |
|   output  | The message that will be shown in the notification |
|  priority |       The “logging level” of the notification      |

---

##### Useful Falco commands:
```bash
#  List all defined fields
# https://falco.org/docs/rules/supported-fields/
falco --list

# Apply rules from a custome file 
falco -r <file> 

# run falco for a specific number of seconds
falco -M 

# Run a custom file for 30 seconds
falco -r <file.yml> -M 30
```

##### Overriding default Falco rules:
```bash
vi /etc/falco/falco_rules.yaml # Copy the rule that we need to change 
vi /etc/falco/falco_rules.local.yaml 
```

<details>
<summary>falco_rules.local.yaml</summary>
<p>

```yaml
- rule: Terminal shell in container
  desc: A shell was used as the entrypoint/exec point into a container with an attached terminal.
  condition: >
    spawned_process and container
    and shell_procs and proc.tty != 0
    and container_entrypoint
    and not user_expected_terminal_shell_in_container_conditions
  output: >
    A shell was spawned in a container with an attached terminal (user=%user.name user_loginuid=%user.loginuid %container.info
    shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline terminal=%proc.tty container_id=%container.id image=%container.image.repository)
  priority: WARNING # Changed from NOTICE to WARNING
  tags: [container, shell, mitre_execution]
```

</p>
</details>

- If we run the command `falco` then `falco_rules.yaml` is read first then `falco_rules.local.yaml` is read after it thus overriding the rule.

---

#### :small_blue_diamond: 5. Ensure immutability of containers at runtime:
- Container [immutability](http://chadfowler.com/2013/06/23/immutable-deployments.html) means that the container won't be modified during its lifetime
- This adds more reliability and better security on container level, it also allows easy rollbacks.

#### Enforce immutability on a container level:
- Disable privileged mode `securityContext.privileged: false`
- Disable privilege escalation `securityContext.allowPrivilegeEscalation: false`
- Remove bash/sh from the container
- Make Filesystem read-only using **SecurityContext** or **PodSecurityPolicy** `readOnlyRootFilesystem: true`
- Run as specific user, never run as root ~~`securityContext.runAsUser: 0`~~

##### Ways to do it in Kubernetes:
1. Make manual changes to the `command` (Override the default ENTRYPOINT) `chmod a-w-R && nginx`
2. Use **StartupProbe** to execute the command (StartupProbe gets executed before readiness and liveness probes) `chmod a-w-R /`
3. Use securityContext and PodSecurityPolicy **Preferred solution**
4. Use `InitContainer` to do the command execution and modify the files (the initContainer will be given **RW** permissions) then the app container will be given only read permission

---

#### :small_blue_diamond: 6.Use Audit Logs to monitor access:
- Any request made to the kubernetes API server should be logged (This forms our Audit logs)
- Audit logs allow us to answer questions like:
  - When was the last time user X accessed cluster Y
  - Did someone access a secret while it wasn't protected ?
  - Does CRDs work properly ?
- Each request can be recorded with an associated stage, these are:
  1. RequestReceived # Stage for events generated whenever the API server receives the request
  2. ResponseStarted # Once the response headers are sent but before the response body is sent (this stage is generated only for long-running requests like `watch`)
  3. ResponseComplete # Response body has completed
  4. Panic 
- Each of the aforementioned stages is compared against the rules specified using the next 4 audit levels:
  1. None # don't log events that match this rule
  2. Metadata # Log metadata (requesting user, timestamp, resource and verb)
  3. Request # Logs metadata + request body
  4. RequestResponse # Log metadata + request body + response body 

##### Configure API server to store audit logs in JSON format:
```yaml
mkdir -pv /etc/kubernetes/audit
vi /etc/kubernetes/audit/simple.yml

apiVersion: audit.k8s.io/v1 
kind: Policy 
rules:
- level: Metadata 

# Enable auditing in the manifests through kube-apiserver.yaml
vi /etc/kubernetes/manifests/kube-apiserver.yaml
# From the documentation grab the flags needed https://kubernetes.io/docs/tasks/debug-application-cluster/audit/#log-backend
--audit-policy-file
--audit-log-path 
--audit-log-maxsize # Max size in Megabytes
--audit-log-maxbackup # Max number of audit logs to retain

# Add the policy folder as a volume and mount it 
volumes:
- name: audit-v
  hostPath:
    path: /etc/kubernetes/audit
    type: DirectoryOrCreate

volumeMounts:
- name: audit-v
  mountPath: /etc/kubernetes/audit
```

##### Create a secret and investigate the audit log:
```yaml
k create secret generic audit-secret --from-literal=user=admin
sudo cat /etc/kubernetes/audit/logs/audit.log | grep audit-secret | jq
```

##### Investigate API access history of a secret:
- Change audit policy file to include Request + Response from secrets
- Create a new ServiceAccount (which generates a new secret) and confirm that request + response are available. 
- Create a pod that uses the SA

```yaml
vi /etc/kubernetes/audit/policy.yml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
- "RequestReceived"
rules:
- level: None
  verbs: ["get", "watch", "list"]
- level: RequestResponse
  resources:
  - group: ""
    resources: ["secrets"]       

k create sa random-sa
cat /etc/kubernetes/audit/logs/audit.log | grep random-sa | jq
```

##### Recommendations for writing Audit policies:
1. For sensitive resources like `secrets`, `ConfigMaps` and `TokenReviews` only log at **Metadata** level
- If responses were also stored this reults in exposing sensitive data
```yaml
- level: Metadata
  resources:
  - group: ""
    resources:
    - secrets
    - configmaps
    - tokenreviews
```


2. Don't log read-only URLS
```yaml
- level: None 
  nonResourceURLs:
  - '/healthz*'
  - '/version'
  - '/swagger*'
```

3. Log at least Metadata level for all resources
4. Log at RequestResponse level for critical resources

---
---

Qs:

### CKS Exam Series:
#### :clipboard: 3- [Immutable Pods](https://itnext.io/cks-exam-series-3-immutable-pods-3812cf76cff4):
1. Create Pod holiday with two containers c1 and c2 of image bash:5.1.0, ensure the containers keep running.
```yaml
k run holiday --image=bash:5.1.0 $do > holiday.yml --command sleep 3600
vi holiday.yml

apiVersion: v1
kind: Pod
metadata:
  labels:
    run: holiday
  name: holiday
spec:
  containers:
  - command:
    - sleep
    - "3600"
    image: bash:5.1.0
    name: c1
  - name: c2
    image: bash:5.1.0
    command:
    - sleep
    - "3600"
```

2. Create Deployment snow of image nginx:1.19.6 with 3 replicas
```bash
k create deploy snow --image=nginx:1.19.6 --replicas=3 $do > snow.yml
k apply -f snow.yml
```

3. Force container c2 of Pod holiday to run immutable: no files can be changed during runtime
```yaml
k delete po holiday --force --grace-period=0
k explain pod.spec.containers --recursive | grep read
vi holiday.yml
- name: c2
  image: bash:5.1.0
  command:
  - sleep
  - "3600"
  securityContext:
    readOnlyRootFilesystem: True
```

4. Make sure the container of Deployment snow will run immutable. Then make necessary paths writable for Nginx to work.
```yaml
k edit deploy snow 
containers:
- image: nginx:1.19.6
  imagePullPolicy: IfNotPresent
  name: nginx
  resources: {}
  securityContext:
    readOnlyRootFilesystem: true

k annotate deployments.apps snow kubernetes.io/change-cause="make read only FS"
```

This results in errors as follows:
```
2020/12/21 13:51:11 [emerg] 1#1: mkdir() "/var/cache/nginx/client_temp" failed (30: Read-only file system)
nginx: [emerg] mkdir() "/var/cache/nginx/client_temp" failed (30: Read-only file system)
```
To solve this a volume needs to be mounted to `/var/cache/`

```yaml
k edit deploy snow
spec:
  volumes:
  - name: cache-v
    emptyDir: {}
  containers:
  - image: nginx:1.19.6
    imagePullPolicy: IfNotPresent
    name: nginx
    volumeMounts:
    - name: cache-v 
      mountPath: /var/cache

k annotate deploy snow kubernetes.io/change-cause="Add cache-v volume"
```

---

* Create namespaces red and blue
* User Jane can only get secrets in ns red 
* User Jane can only get and list secrets in ns blue 
* Test using can-i 
```bash
k create ns blue 
k create ns red 

# Create user Jane
openssl genrsa -out jane.key 2048
openssl req -new -key jane.key -out jane.csr -subj "/CN=jane"
# Create CSR object using the yaml definition from the documentation https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#create-certificatesigningrequest
k apply -f jane-csr.yml
k get csr
k certificate approve Jane
k get csr Jane -o jsonpath='{.status.certificate}' | base64 -d > jane.crt
k config set-credentials jane --client-certificate=jane.crt --client-key=jane.key --embed-certs
k create role role1 --verb=get --resource=secrets --namespace=red 
k create role role2 --verb=get,list --resource=secrets --namespace=blue 
k create rolebinding rb1 --role role1 --user jane --namespace red
k auth can-i get secret --as=jane -n red # yes 
k create rolebinding rb2 --role role2 --user jane --namespace blue
```

* Create a ClusterRole **deploy-deleter** which allows us to delete deployments 
* User jane can delete deployments in all namespaces 
* User Jim can delete deployments only in namespace red
* Test it using `auth can-i`

```bash
openssl genrsa -out jim.key 2048
openssl req -new -key jim.key -out jim.csr -subj "/CN=jim"
# Create CSR object using the yaml definition from the documentation https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#create-certificatesigningrequest
k apply -f jim-csr.yml
k get csr
k certificate approve jim
k get csr jim -o jsonpath='{.status.certificate}' | base64 -d > jim.crt
k config set-credentials jim --client-certificate=jim.crt --client-key=jim.key --username=jim --embed-certs

k create clusterrole deploy-deleter --verb=delete --resource=deploy $do
k create clusterrolebinding crb1 --clusterrole=deploy-deleter --user=jane
k create rolebinding  jim-rb --clusterrole=deploy-deleter --user=jim --namespace red
```

---

Restrict the logged data with an audit policy so that:
1. Nothing from stage RequestReceived is stored
2. Nothing from "get", "watch" and "list" is stored
3. From secrets only Metadata is stored
4. Everything else at RequestResponse level

```yaml
apiVersion: audit.k8s.io/v1 
kind: Policy
omitStages:
  - "RequestReceived" # 1. Nothing from stage RequestReceived is stored
rules:
- level: None 
  verbs: ["get", "watch", "list"] # Nothing from "get", "watch" and "list" is stored

- level: Metadata 
  resources:
  - group: ""
    resources: ["secrets"] # From secrets only Metadata is stored

- level: RequestResponse # Everything else at RequestResponse level

```

---

#### 4- :clipboard: [Crash that Apiserver & check logs](https://itnext.io/cks-exam-series-4-crash-that-apiserver-5f4d3d503028):

1. Configure the Apiserver manifest with a new argument --this-is-very-wrong. Check if the Pod comes back up and what logs this causes. Fix the Apiserver again.
```yaml
vi /etc/kubernetes/manifests/kube-apiserver.yaml
containers:
- command:
  - kube-apiserver
  - --this-is-very-wrong

# Check api server pod logs
cat /var/log/pods/kube-system_kube-apiserver-master_3acb7548a2e6921effda24ba19220d6c/kube-apiserver/2.log
{"log":"Error: unknown flag: --this-is-very-wrong\n","stream":"stderr","time":"2021-01-12T18:59:48.673662719Z"}
```

2. Change the existing Apiserver manifest argument to: —-etcd-servers=this-is-very-wrong. Check what the logs say, and fix it again.
```yaml
vi /etc/kubernetes/manifests/kube-apiserver.yaml
containers:
- command:
  - kube-apiserver
  - --etcd-servers=this-is-very-wrong

# Try to execute any kubectl command 
k get po

> Unable to connect to the server: net/http: TLS handshake timeout

cat /var/log/pods/kube-system_kube-apiserver-master_13a1f8b644ce59316e62202a601b47e7/kube-apiserver/3.log 
Error while dialing dial tcp: address this-is-very-wrong: missing port in address\". Reconnecting...\n","stream":"stderr","time":"2021-01-12T19:03:32.061085256Z"}
{"log":"I0112 19:03:33.055244       1 client.go:360] parsed scheme: \"endpoint\"\n","stream":"stderr","time":"2021-01-12T19:03:33.055525393Z"}
```

3. Change the Apiserver manifest and add invalid YAML. Check what the logs say, and fix again.
```bash
# No logs for api server were generated after breaking the YAML file so we can check kubelet logs instead
journalctl -u kubelet
```


---

#### 5- :clipboard: [ImagePolicyWebhook / AdmissionController](https://itnext.io/cks-exam-series-5-imagepolicywebhook-8d09f1ceee70):

---
---

### Irrelevant to CSK but valuable regarding security:
#### 1.Never store sensitive information in an image:
* This example is from the book **container security** by Liz Rice
```Dockerfile
FROM alpine 
RUN echo "password" > /password.txt 
RUN rm /password.txt 
```

```bash
# Build the image and check for the file 
sudo docker build . -t sensitive
docker run --rm -it sensistive cat /password.txt # File doesn't exist
docker save sensitive > sensitive.tar
mkdir sensitive && cd $_ && mv ../sensitive.tar .
tar xvf sensitive.tar 
cat manifest.json # First line displays the config file
cat 7480*.json | jq '.history'
```

<details>
<summary>JSON output</summary>
<p>

```json
[
  {
    "created": "2020-12-17T00:19:41.960367136Z",
    "created_by": "/bin/sh -c #(nop) ADD file:ec475c2abb2d46435286b5ae5efacf5b50b1a9e3b6293b69db3c0172b5b9658b in / "
  },
  {
    "created": "2020-12-17T00:19:42.11518025Z",
    "created_by": "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
    "empty_layer": true
  },
  {
    "created": "2020-12-29T11:17:07.969695162Z",
    "created_by": "/bin/sh -c echo \"Password\" > /password.txt"
  },
  {
    "created": "2020-12-29T11:17:08.566905631Z",
    "created_by": "/bin/sh -c rm /password.txt"
  }
]
```

</p>
</details>

```bash
# Extract files from the layer 
tar -xvf 173af461747ed9252ce5c8241a8e2dfbe85ef7a838945445be6ada05f7c6a883/layer.tar
cat password.txt # Shows password 
```

#### 2. Running containers with runc:
1. Get the rootfs of the image desired
```bash
mkdir rootfs
docker cp <id>:/ rootfs/

# Generate config.json 
runc spec

# Run container using runc 
runc run <name>

# From another tab check the containers list running using runc 
runc list
```

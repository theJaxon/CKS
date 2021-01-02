# CKS
![CKS](https://img.shields.io/badge/-CKS-0690FA?style=for-the-badge&logo=kubernetes&logoColor=white)
![K8s](https://img.shields.io/badge/-kubernetes-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white)

Preparation for Certified Kubernetes Security Specialist (CKS) Exam V1.19

---

#### :open_file_folder: Important Dirs:
```bash
# Inside the pod 
/run/secrets/kubernetes.io/serviceaccount
  /token # The token from the secret that gets created with the sa is here

```

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
```

#### NetworkPolicies:
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

#### Ingress:
Generate new self signed certificate
```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

---

#### ServiceAccounts:
Disable SA token to prevent the pod from talking to the kubernetes-api
* Can be done on the level of the SA itself, in metadata section set `automountServiceAccountToken: False`
* Can be done on the pod level, in spec `automountServiceAccountToken: False`

---
---

### :purple_circle: Cluster Hardening:
#### 1. Restrict access to kubernetes API:
What happens when a request gets sent to the kuberntes API?
When a request is sent to the kubernetes API it goes through 3 levels of checks:
* Authentication check (Who is the one making the request)
* Authorization check (Are you allowed to perform the action)
* Admission control check (ex: can new pods be created or we reached a max, in this case even if you can do the action of creating pods you'll be denied by the admission controller)

API requests are tied to:
* Normal user
* Service account 
* Anonymous request (If the request didn't authenticate)

To restrict API access you should:
1. Block anonymous access
2. Close insecure port 
3. Don't expose kube-apiserver to the outside
4. Restrict access from nodes to API **NodeRestriction**
5. Prevent unauthorized access using RBAC
6. Prevent pods from accessing API `automountServiceAccountToken: False`

##### 1.Block anonymous access:
* In `/etc/kubernetes/manifests/kube-apiserver.yaml` the **--anonymous-auth** flag can be set to true or false.
* Anonymous access is enabled by default.
* RBAC requires explicit authorization for anonymous access.

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
- Pod security policy is an admission controller which controls under which security conditions a pod has to run
- Can be enabled by modifying kube-apiserver manifest `--enable-admission-plugins=PodSecurityPolicy`

```yaml
spec:
  privileged: False
  allowPrivilegeEscalation: False 
  # The rest fills in some required fields.
```
- This ensures that privileged pods or those who allow privilege escalation will not be created.
- The default service account need to be modified so that the newly created deployment work with the PodSecurityPolicy
 
```bash
k create role psp-access --verb=use --resource=podsecuritypolicies
k create rolebinding psp-access --role=psp-access --serviceaccount=default:default
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
This is done by creating an [**`EncryptionConfiguration`**](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/) object and passing this object to the API server `--encryption-provider-config` which is the component responsible for communicating with ETCD.

How EncryptionConfiguration works?
- Under `resources` we specify the resources to be encrypted
- Under `providers` section we specify an array of providers:
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
---

Qs:

#### CKS Exam Series:
3- [Immutable Pods](https://itnext.io/cks-exam-series-3-immutable-pods-3812cf76cff4):
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

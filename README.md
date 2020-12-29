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

#### 3.Don't expose kube-apiserver to the outside:
Make the api-server accessible externally by modifying the `kubernetes` svc and changing its type to `NodePort`
```bash
k edit svc kubernetes
type: NodePort
```
* From a different machine curl the <node-ip>:<k8s-svc-port> and it works
* curl with -k to authenticate as anonymous user
* Copy the kubeconfig file on the host `scp <user>@<ip>:/home/<user>/.kube/conf .`
* Access externally using kubectl as `kubectl --kubeconfig conf get po`

#### 4.Restrict access from nodes to API using NodeRestriction admission controller:
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

#### Connecting to the API server manually with certificates:
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
#### 3. Manage kubernetes secrets
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

* Encrypting ETCD and secrets inside it
This is done by creating an **`EncryptionConfiguration`** object and passing this object to the API server `--encryption-provider-config` which is the component responsible for communicating with ETCD.



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
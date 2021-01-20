##### Simulating maybe:
1. Given the following rego block, create a policy that enforces pods to be labelled with keys `app` and `version`
```rego
violation[{"msg": msg, "details": {"missing_labels": missing}}] {
provided := {label | input.review.object.metadata.labels[label]}
required := {label | label := input.parameters.labels[_]}
missing := required - provided
count(missing) > 0
msg := sprintf("you must provide labels: %v", [missing])
}
```

- Search in the documentation for the term **OPA**
<details>
<summary> - create a constraintTemplate </summary>
<p>

```yaml
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
        listKind: K8sRequiredLabelsList
        plural: k8srequiredlabels
        singular: k8srequiredlabels
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          properties:
            labels:
              type: array
              items: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels
        violation[{"msg": msg, "details": {"missing_labels": missing}}] {
        provided := {label | input.review.object.metadata.labels[label]}
        required := {label | label := input.parameters.labels[_]}
        missing := required - provided
        count(missing) > 0
        msg := sprintf("you must provide labels: %v", [missing])
        }
```

</p>
</details>

<details>
<summary>- Create constraint</summary>
<p>

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: ns-must-have-hr
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
  parameters:
    labels: ["app", "version"]
```

</p>
</details>

Verify 
```bash
k run nginx --image=nginx
Error from server ([denied by ns-must-have-hr] you must provide labels: {"app", "version"}): admission webhook "validation.gatekeeper.sh" denied the request: [denied by ns-must-have-hr] you must provide labels: {"app", "version"}
```

---

2. Create a policy that prevents the use of `hostPath` volume type
- create PSP object
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: permissive
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: '*'
spec:
  privileged: true
  allowPrivilegeEscalation: true
  allowedCapabilities:
  - '*'
  volumes:
  - '*'
  hostNetwork: true
  hostPorts:
  - min: 0
    max: 65535
  hostIPC: true
  hostPID: true
  runAsUser:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
```

```bash
# Create a generic role to allow pods in kube-system to keep functioning after enabling PSP admission controller
k create clusterrole permissive --verb=use --resource=psp --resource-name=permissive $do > permissive-clusterrole.yml

# Create rolebinding 
k create rolebinding permissive --clusterrole=permissive --group=system:authenticated -n kube-system $do > permissive-rolebinding.yml
```

- Create restrictive PSP
```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restrictive
spec:
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
```

```bash
# Create restrictive role 

```

---

3. Prevent pods from reaching the address `169.254.169.254` as it exposes node metadata

<details>
<summary>NetworkPolicy.yml</summary>
<p>

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  podSelector: {} # Apply on all pods
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
      cidr: 0.0.0.0/0 # Access anything  
      except: 
      - 169.254.169.254/32 # Except metadata address
```

</p>
</details>

---

4. Given that the webhook webserver is available at `bouncer.local.lan`, configure the cluster so that ImagePolicyWebhook admission controller is enforced

---

5. Enable audit policy and configure it as follows:

---

6. Check anomalies using falco and format the log output as follows:

---

7. Create a deployment that relies on gVisor (uses runsc runtime handler)

---

8. Create a PodSecurityPolicy that disables privilege escalation and privileged containers from running

---

9. Resolve security issues detected by kube-bench on the master and worker node

---

10. Analyze Dockerfile in order to fix security issues

---

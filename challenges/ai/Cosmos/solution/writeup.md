## Challenge Write-up: Clustering-based Flag Extraction

### Overview

In this challenge, we were presented with a `520x17` dataset (`cosmos.csv`) containing points in a 17-dimensional space. The hidden flag was known to be a 17-character string, and our task was to recover it by performing clustering and decoding the centroid coordinates.

### Approach

1. **Elbow Method (Inertia)**

   * We computed the K-means inertia for `k` ranging from 1 to 10.
   * By plotting inertia vs. `k`, we identified an "elbow" at `k = 6`, indicating that six clusters best capture the data structure without overfitting.

2. **Data Standardization**

   * Since K-means is sensitive to the scale of features, we standardized each dimension to zero mean and unit variance using `StandardScaler`.

3. **K-means Clustering**

   * We fit `KMeans(n_clusters=6, random_state=0)` on the standardized data matrix `Xs`.
   * Extracted the six cluster centroids in standardized space.

4. **Flag Decoding**

   * For each centroid:

     1. Converted it back to original scale: `c_orig = c_scaled * scaler.scale_ + scaler.mean_`.
     2. Rounded each of its 17 coordinates to the nearest integer.
     3. Mapped each integer to its corresponding ASCII character.
     4. Joined the characters to form a 17-character candidate flag.
   * Printed all six candidates and identified the valid flag by pattern matching (e.g. uppercase letters and underscores).

### Code Snippet

```python
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans

# Load data
df = pd.read_csv('cosmos.csv')
X = df.values

# Standardize
scaler = StandardScaler()
Xs = scaler.fit_transform(X)

# Fit K-means
kmeans = KMeans(n_clusters=6, random_state=0).fit(Xs)
centroids = kmeans.cluster_centers_

# Decode flags
flags = []
for idx, c_scaled in enumerate(centroids, start=1):
    c_orig = c_scaled * scaler.scale_ + scaler.mean_
    codes = np.rint(c_orig).astype(int)
    flag = ''.join(chr(code) for code in codes)
    flags.append(flag)
    print(f"Cluster {idx} flag: {flag}")
```

### Result

Out of the six decoded strings, the valid flag was:

```
clu5ter5_4r3_c00l
```

### Conclusion

By combining the Elbow Method to determine the optimal number of clusters and a straightforward decoding of centroid coordinates back to ASCII, we successfully extracted the 17-character flag hidden in the 6th cluster. This approach generalizes to any dimensionally-encoded flag planted as a tight Gaussian cluster among decoys.

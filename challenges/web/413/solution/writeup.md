# Writeup

413 Challenge

## Solution

The challenge is a simple web interface with text input and a button to submit. The goal is to find a way to bypass the nginx body size limit of 200 bytes to send 200 text characters in text field.

the real solution is to use the javascript known vunrability called **Type Confusion** to bypass the nginx body size limit by tricking the server into thinking that the text length is more than 200 characters, while in reality it is an object.

### Steps to solve the challenge:

- using postman , SET a POST request to the challenge submit url `/submit` using application/x-www-form-urlencoded content type.

```
text[length]=300
```

- in the body of the request, set the text field to a javascript object that has a `length` property set to 300, like this:

```javascript
{"length":"300"}
```

- since in javascript the `length` property of an object is not the same as the length of the string representation of the object, the server will think that the text field has a length of 300 characters, while in reality it is an object , the comparision will work since javascript implicitly converts '300' to a number when comparing it to the length property of the object.

- the server will accept the request and return a success message, indicating that the text field has been successfully submitted.

'use strict';


// AuthPlz API interface class
class AuthPlzApi {
    constructor() {

    }

    Status() {
        // Call fetch
        fetch('/api/status').then(res => {
            if(res.ok) {
                console.log("Successful get from /api/status")
            } else {
                console.log("Failed to get from /api/status")
            }
        })
    }

    Get(path, data) {
        return new Promise((resolve, reject) => {
            // Call fetch
            fetch(path, {
                method: 'get'
            }).then((res) => { return res.json(); })
            .then((data) => {
                if(data.result === "ok") {
                    resolve(data.message)
                } else {
                    reject(data.message)
                }
            }, (err) => {
                console.log("Failed to get from: " + path + " error: " + err)
                reject("Communication error or bad request")
            })  
        })
    }

    Post(path, data) {
        var formData = new FormData();
        for(let i in data) {
            formData.append(i, data[i]);
        }

        return new Promise((resolve, reject) => {
            // Call fetch
            fetch(path, {
                method: 'post',
                body: formData
            }).then((res) => { return res.json(); })
            .then((data) => {
                if(data.result === "ok") {
                    resolve(data.message)
                } else {
                    reject(data.message)
                }
            }, (err) => {
                console.log("Failed to post to: " + path)
                reject("Communication error or bad request")
            })  
        })
    }

    CreateUser(email, password) {
        return this.Post('/api/create', {email: email, password: password})
    }

    Login(email, password) {
        // Create formdata to send
        var formData = new FormData();
        formData.append("email", email);
        formData.append("password", password);

        // Call fetch
        fetch('/api/login', {
            method: 'post',
            body: formData
        }).then(res => {
            if(res.ok) {
                console.log("Successful post to /api/login")
            } else {
                console.log("Failed to post to /api/login")
            }
        })
    }

}

console.log("Loading AuthPlz API")
const AuthPlz = new AuthPlzApi()


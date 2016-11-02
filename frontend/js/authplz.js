'use strict';


// AuthPlz API interface class
class AuthPlzApi {
    constructor() {

    }

    // API get helper
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

    // API post helper
    PostForm(path, data) {
        var formData = new FormData();
        for(let i in data) {
            formData.append(i, data[i]);
        }

        return new Promise((resolve, reject) => {
            // Call fetch
            fetch(path, {
                method: 'post',
                body: formData
            }).then((res) => { 
                return res.json();
            })
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

    Status() {
        return this.Get('/api/status')
    }

    CreateUser(email, password) {
        return this.PostForm('/api/create', {email: email, password: password})
    }

    Login(email, password) {
        return this.PostForm('/api/login', {email: email, password: password})
    }

}

const AuthPlz = new AuthPlzApi()
export {AuthPlz, AuthPlzApi}


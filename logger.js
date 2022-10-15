const EventEmitter = require("events")

class Logger extends EventEmitter {
    log(message) {
        console.log(message)

        this.emit("LoggedMessage", message)
    }
}

module.exports = Logger
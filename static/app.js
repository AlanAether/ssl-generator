async function generate() {
    const domain = document.getElementById("domain").value
    const email = document.getElementById("email").value

    const res = await fetch("/generate", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, email })
    })

    if (!res.ok) {
        document.getElementById("output").innerText = "Error: " + res.status
        return
    }

    const data = await res.json()

    document.getElementById("output").innerText =
        data.message +
        "\n\nDNS Name: " + data.dns_name +
        "\nTXT Value: " + data.dns_value
}

async function finalize() {
    const domain = document.getElementById("domain").value

    const res = await fetch("/finalize", {
        method: "GET",
        credentials: "include"
    })

    const text = await res.text()

    document.getElementById("output").innerHTML =
        text +
        "<br><br><a href='/download-cert?domain=" + domain + "'>Download Certificate</a>" +
        "<br><a href='/download-key?domain=" + domain + "'>Download Private Key</a>" +
        "<br><a href='/download-bundle?domain=" + domain + "'>Download CA Bundle</a>"
}

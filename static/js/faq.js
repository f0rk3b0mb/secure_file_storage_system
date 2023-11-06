function show() {
    bar = document.getElementById("q_bar");
    bar.style.height = "100px"
    bar.childNodes[3].hidden = false;
}

function hide() {
    bar = document.getElementById("q_bar");
    bar.style.height = "40px"
    bar.childNodes[3].hidden = true;
}
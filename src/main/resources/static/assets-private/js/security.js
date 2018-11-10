var loginJson;
var windowId;

/**
 * Ask the server whether we have authenticated, and show/hide/etc.
 * portions of our page based on the status.
 */
function checkLogin() {
  $.ajax({
    url: "login-status",
    dataType: "json"
  }).done(function(json) {
    loginJson = json;
    if (loginJson.authenticated) {
      $(".show-if-noauth").hide();
      $(".show-if-auth").show();
      $(".user-display-name").text(loginJson.userDisplayName);
      $("#logoutButton").click(logout);
    } else {
      $(".show-if-noauth").show();
      $(".show-if-auth").hide();
      $("#loginButton").click(login);
    }
  });
}

/**
 * Send the browser to the centralized login page, preserving the
 * current page in the history (so the user can go back from the
 * login if they change their mind).
 */
function login() {
  if (window.location.search || window.location.hash) {
    window.name = "windowId:" + windowId + ";q=" + window.location.search + window.location.hash;
  }
  if (loginJson.loginUrl) {
    window.location.href = loginJson.loginUrl;
  } else {
    window.location.reload(true);
  }
}

/**
 * Send the browser to the local logout page, replacing the current
 * page in the history (so they can't go back and view the contents
 * after logout). The local logout will redirect us to the centralized
 * logout.
 */
function logout() {
  window.location.replace("logout");
}

/**
 * Use a random id to distinguish this window/tab from others in case
 * the user opened multiple (helps prevent undesirable cross-talk and
 * keeps our logs distinguishable). Note this is client-generated, so
 * it should not be used for any session/security purposes.
 */
function initializeWindowId() {
  var match = window.name.match(/windowId:([^;]+)(;q=(.*))?/);
  if (match) {
    windowId = match[1];
  } else {
    windowId = Math.floor(Math.random()*1e16).toString(36).slice(0, 8);
  }
  window.name = "windowId:" + windowId;
  if (match && match[3]) {
    window.location.href = window.location.href + match[3];
    return false;
  } else {
    return true;
  }
}

$(function() {
  if (initializeWindowId()) {
    $.ajaxSetup({
      beforeSend: function (xhr) {
        // Attach a unique id for this window/tab (see comments above)
        xhr.setRequestHeader("X-WINDOW-ID", windowId);

        // Read an XSRF token from a cookie and place it in a header to
        // prove we have access to it (same domain)
        document.cookie.split(';').forEach(function (s) {
          if (s.substr(0, 10) === "XSRF-TOKEN=") {
            xhr.setRequestHeader("X-XSRF-TOKEN", s.substr(11));
          }
        });
      }
    });

    $(document).ajaxError(function (event, xhr, settings, error) {
      if (xhr.status === 401) {
        if (xhr.getResponseHeader("WWW-Authenticate").match(/Redirect .+/)) {
          // By convention, we use "Redirect https://..." to tell the client where to
          // redirect for an OpenId Connect authentication
          if (window.location.search || window.location.hash) {
            // The login redirect will lose our query string, so stash it temporarily
            window.name = "windowId:" + windowId + ";q=" + window.location.search + window.location.hash;
          }
          window.location.href = xhr.getResponseHeader("WWW-Authenticate").substr(9);
        } else {
          login();
        }
      } else if (xhr.status === 0) {
        alert("The server is not available right now");
      } else {
        alert("Error: " + xhr.status + ": " + error);
      }
    });

    checkLogin();
  }
});

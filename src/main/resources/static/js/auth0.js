import { createAuth0Client } from '@auth0/auth0-spa-js';

const auth0 = await createAuth0Client({
  domain: 'sonatype-mtiq-test.us.auth0.com',
  clientId: 'ZggGCC7hcC6LYvdpjOfZAA29dixIRBrx'
});

document.getElementById('login').addEventListener('click', (ev) => {
  ev.preventDefault();
  auth0.loginWithRedirect({
    authorizationParams: {
      redirect_uri: 'http://localhost:8080'
    }
  }).then(token => {
    //logged in. you can get the user profile like this:
    auth0.getUser().then(user => {
      console.log(user);
    });
  });
});

// document.getElementById('callApi').addEventListener('click', async () => {
//   const accessToken = await auth0.getTokenSilently();
//   const result = await fetch('https://localhost:8080/api', {
//     method: 'GET',
//     headers: {
//       Authorization: 'Bearer ' + accessToken
//     }
//   });
//   const data = await result.json();
//   console.log(data);
// });

// $('#logout').click(async () => {
//   auth0.logout({
//     logoutParams: {
//       returnTo: 'http://localhost:8080/'
//     }
//   });
// });

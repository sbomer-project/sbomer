// for development purposes, you can change the backend url here
// this URL is overriden in a container environment by the run-with-env.sh script

// Currently not working, if a change is needed, the frontent code must be changed to
// take this instead of the hardcorded URL value

// Kept for backward compatibility with existing setups
window._env_ = {
  API_URL: "http://localhost:8080/",
};

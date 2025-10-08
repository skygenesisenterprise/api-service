import axios from 'axios';

export const authenticate = async (username: string, password: string) => {
  const response = await axios.post('https://sso.skygenesisenterprise.com/auth', {
    username,
    password
  });

  if (response.status === 200) {
    return response.data;
  } else {
    throw new Error('Authentication failed');
  }
};

export default { authenticate };
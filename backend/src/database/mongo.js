import { MongoClient } from 'mongodb';

export const Mongo = {
  async connect({ mongoConectionString, mongoDbName }) {
    try {
      const client = new MongoClient(mongoConectionString);

      await client.connect();
      const db = client.db(mongoDbName);

      this.client = client;
      this.db = db;

      return 'Connected to Mongo!';

    } catch (error) {
      return { text: 'Error during mongo connect', error };
    }
  },
};

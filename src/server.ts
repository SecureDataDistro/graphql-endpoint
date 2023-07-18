import { ApolloServer, BaseContext } from "@apollo/server";
import { GraphQLError } from 'graphql';
import {JWT} from "@hub/jwt"
import { Authorizer } from "@hub/iam";

import { expressMiddleware } from '@apollo/server/express4';
import { ApolloServerPluginDrainHttpServer } from '@apollo/server/plugin/drainHttpServer';
import express from 'express';
import http from 'http';
import cors from 'cors';
import bodyParser from 'body-parser';

export interface GraphqlServerConfig {
    serverPort: number
    publicKeyEndpoint: string
    resourceURN: string
}

export interface AuthContext extends BaseContext {
    jwt: JWT | undefined
}

export async function StartApolloStandaloneServer(config: GraphqlServerConfig, typeDefs: any, resolvers: any) {
    
    const app = express();
    const httpServer = http.createServer(app);
    
    const server = new ApolloServer<AuthContext>({
        //schema: buildSubgraphSchema({ typeDefs, resolvers }),
        typeDefs,
        resolvers,
        plugins: [ApolloServerPluginDrainHttpServer({ httpServer })]
    });

    await server.start();

    const auth = new Authorizer(config.publicKeyEndpoint);

    app.use(
      '/graphql',
      cors<cors.CorsRequest>(),
      // 50mb is the limit that `startStandaloneServer` uses, but you may configure this to suit your needs
      bodyParser.json({ limit: '50mb' }),
      // expressMiddleware accepts the same arguments:
      // an Apollo Server instance and optional configuration options
      expressMiddleware<AuthContext>(server, {
        context: async ({ req, res }) => {
            // Get the user token from the headers.
            // look for x-sdd-user-token
            // or x-ssd-router-token
            const routerToken: string | undefined = req.headers['x-sdd-router-token'] as string || undefined;
            const userToken: string | undefined = req.headers["x-sdd-user-token"] as string || undefined;

            // all connections must have a router token
            if (!routerToken) {
                // if router token doesnt exist then we dont have a token
                throw new GraphQLError('router token is not present', {
                  extensions: {
                    code: 'UNAUTHENTICATED',
                    http: { status: 401 },
                  },
                });
            }

            if (!await auth.isVerified(routerToken)) {
                throw new GraphQLError('router token cannot be verified', {
                    extensions: {
                    code: 'UNAUTHENTICATED',
                    http: { status: 401 },
                    },
                });
            }


            // default to user token if available
            if (!userToken) {
                console.warn("user token is not present");
                return {jwt: undefined};
            }

            // user token verification
            const jwt = await auth.isVerified(userToken);

            if (!jwt) {
                console.warn("user token cannot be validated");
                return {jwt: undefined};
            }
        
            // Add the user to the context
            return { jwt };
          }
        }
      ),
    );

    app.get('/health', (req, res) => {
      res.status(200).send('ok');
    });
    
    // Modified server startup
    await new Promise<void>((resolve) => httpServer.listen({ port: config.serverPort }, resolve));
    console.log(`🚀 Server ready at http://localhost:4000/`);
}
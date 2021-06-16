/**
 * @file Messaging between web content and extension.
 *
 * For this, we use a 'web_accessible_resource' page that a web page can embed
 * in an iframe. The parent content frame and the embedded extension frame can
 * then `postMessage` with each other.
 */

import * as protocol from './protocol';

let addedMessageListener = false;
const connectionsPromised: {[origin: string]: Promise<ExtConnection>} = {};
const connectionsRequested: {[origin: string]: {resolve: any; reject: any}} = {};
const responseHandlers: {[handlerKey: string]: {resolve: any; reject: any}} = {};

/**
 * A communication channel with an extension.
 *
 * It supports a basic request-response kind of interaction (web content is
 * the requester). The meaning of the requests and responses are defined in
 * another layer of abstraction.
 *
 * Use `create` to create one.
 */
export class ExtConnection {
    origin: string;
    messageFrame: WindowProxy;
    nextId: number;

    constructor(origin: string, messageFrame: WindowProxy) {
        this.origin = origin;
        this.messageFrame = messageFrame;
        this.nextId = 0;
    }

    request(req: unknown) {
        return new Promise((resolve, reject) => {
            const reqId = this.nextId++;
            const handlerKey = `${this.origin}/${reqId}`;
            responseHandlers[handlerKey] = {resolve, reject};
            this.messageFrame.postMessage(
                {
                    type: protocol.MESSAGE_TYPE_REQUEST,
                    id: reqId,
                    body: req,
                } as protocol.MessageRequest,
                this.origin,
            );
        });
    }
}

export function handleMessage(e: MessageEvent<unknown>) {
    // @ts-expect-error even if .type is missing, it's fine if we get undefined here
    const messageType = e.data.type;
    switch (messageType) {
        case protocol.MESSAGE_TYPE_READY: {
            const m = e.data as protocol.MessageReady;
            if (!(e.origin in connectionsRequested)) break;
            const {resolve, reject} = connectionsRequested[e.origin];
            const connection = new ExtConnection(e.origin, e.source as WindowProxy);
            resolve(connection);
            break;
        }
        case protocol.MESSAGE_TYPE_RESPONSE: {
            const m = e.data as protocol.MessageResponse;
            const handlerKey = `${e.origin}/${m.id}`;
            if (!(handlerKey in responseHandlers)) break;
            const {resolve, reject} = responseHandlers[handlerKey];
            delete responseHandlers[handlerKey];
            if ('err' in m) {
                reject(m.err);
            } else {
                resolve(m.body);
            }
            break;
        }
    }
}

/**
 * Set up a connection with an extension, identified by its origin. This
 * includes adding an iframe to the document. This requires `document.body`
 * to exist.
 *
 * Gives a promise, so await the result. The promise will hang if the user
 * doesn't have the extension installed.
 *
 * This module keeps an inventory of connections that it has already set up,
 * and it'll give you the the connection promise that it already has if it has
 * one.
 *
 * The connection stays open, and there is no disconnect.
 *
 * @param origin This will look like `chrome-extension://xxxxxxxxxxxxxxxxxx`
 */
export function connect(origin: string) {
    if (!addedMessageListener) {
        window.addEventListener('message', handleMessage);
        addedMessageListener = true;
    }
    if (!(origin in connectionsPromised)) {
        connectionsPromised[origin] = new Promise((resolve, reject) => {
            connectionsRequested[origin] = {resolve, reject};
        });

        const iframe = document.createElement('iframe');
        iframe.src = `${origin}/oasis-xu-frame.html`;
        iframe.hidden = true;
        document.body.appendChild(iframe);
    }
    return connectionsPromised[origin];
}

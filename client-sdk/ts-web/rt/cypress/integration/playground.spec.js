/// <reference types="cypress" />

import * as shared from '../../playground/src/shared';

describe('playground', () => {
    it('finishes', () => {
        cy.visit('http://localhost:8080/');
        cy.contains(shared.CYPRESS_DONE_STRING, {timeout: 60_000});
    });
});
'use strict';
const kerberos = require('../lib');
const request = require('request');
const chai = require('chai');
const expect = chai.expect;
const os = require('os');
chai.use(require('chai-string'));

// environment variables. Подставлять нужные ENV сюда
const username = process.env.KERBEROS_USERNAME || 'administrator';
const password = process.env.KERBEROS_PASSWORD || 'Password01';
const realm = process.env.KERBEROS_REALM;
const hostname = process.env.KERBEROS_HOSTNAME;
const port = process.env.KERBEROS_PORT || '80';

describe('Kerberos', function () {
  before(function () {
    if (os.type() === 'Windows_NT') this.skip();
  });

  it('should lookup principal details on a server', function (done) {
    const expected = `airflow/${hostname}@${realm.toUpperCase()}`;
    kerberos.principalDetails('airflow', hostname, (err, details) => {
      if (err) {
        throw new Error(err); // Прочитать полный текст ошибки
      }
      expect(err).to.not.exist;
      expect(details).to.equal(expected);
      done();
    });
  });

  it('should check a given password against a kerberos server', function (done) {
    const service = `airflow/${hostname}`;
    kerberos.checkPassword(username, password, service, realm.toUpperCase(), err => {
      if (err) {
        throw new Error(err); // Прочитать полный текст ошибки
      }
      expect(err).to.not.exist;

      kerberos.checkPassword(username, 'incorrect-password', service, realm.toUpperCase(), err => {
        expect(err).to.exist;
        done();
      });
    });
  });

  it('should authenticate against a kerberos server using GSSAPI', function (done) {
    const service = `airflow@${hostname}`;

    kerberos.initializeClient(service, {}, (err, client) => {
      if (err) {
        throw new Error(err); // Прочитать полный текст ошибки
      }
      expect(err).to.not.exist;

      kerberos.initializeServer(service, (err, server) => {
        if (err) {
          throw new Error(err); // Прочитать полный текст ошибки
        }
        expect(err).to.not.exist;
        expect(client.contextComplete).to.be.false;
        expect(server.contextComplete).to.be.false;

        client.step('', (err, clientResponse) => {
          if (err) {
            throw new Error(err.message); // Прочитать полный текст ошибки
          }
          expect(err).to.not.exist;
          expect(client.contextComplete).to.be.false;

          server.step(clientResponse, (err, serverResponse) => {
            if (err) {
              throw new Error(err.message); // Прочитать полный текст ошибки
            }
            expect(err).to.not.exist;
            expect(client.contextComplete).to.be.false;

            client.step(serverResponse, err => {
              if (err) {
                throw new Error(err.message); // Прочитать полный текст ошибки
              }
              expect(err).to.not.exist;
              expect(client.contextComplete).to.be.true;

              const expectedUsername = `${username}@${realm.toUpperCase()}`;
              expect(server.username).to.equal(expectedUsername);
              expect(client.username).to.equal(expectedUsername);
              expect(server.targetName).to.not.exist;
              done();
            });
          });
        });
      });
    });
  });

  it('should authenticate against a kerberos HTTP endpoint', function (done) {
    const service = `airflow@${hostname}`;
    const url = `http://${hostname}:${port}/`;

    // send the initial request un-authenticated
    request.get(url, (err, response) => {
      if (err) {
        throw new Error(err); // Прочитать полный текст ошибки
      }
      expect(err).to.not.exist;
      expect(response).to.have.property('statusCode', 401);

      // validate the response supports the Negotiate protocol
      const authenticateHeader = response.headers['www-authenticate'];
      expect(authenticateHeader).to.exist;
      expect(authenticateHeader).to.equal('Negotiate');

      // generate the first Kerberos token
      const mechOID = kerberos.GSS_MECH_OID_KRB5;
      kerberos.initializeClient(service, { mechOID }, (err, client) => {
        if (err) {
          throw new Error(err); // Прочитать полный текст ошибки
        }
        expect(err).to.not.exist;

        client.step('', (err, kerberosToken) => {
          if (err) {
            throw new Error(err.message); // Прочитать полный текст ошибки
          }
          expect(err).to.not.exist;

          // attach the Kerberos token and resend back to the host
          request.get(
            { url, headers: { Authorization: `Negotiate ${kerberosToken}` } },
            (err, response) => {
              if (err) {
                throw new Error(err); // Прочитать полный текст ошибки
              }
              expect(err).to.not.exist;
              expect(response.statusCode).to.equal(200);

              // validate the headers exist and contain a www-authenticate message
              const authenticateHeader = response.headers['www-authenticate'];
              expect(authenticateHeader).to.exist;
              expect(authenticateHeader).to.startWith('Negotiate');

              // verify the return Kerberos token
              const tokenParts = authenticateHeader.split(' ');
              const serverKerberosToken = tokenParts[tokenParts.length - 1];
              client.step(serverKerberosToken, err => {
                if (err) {
                  throw new Error(err.message); // Прочитать полный текст ошибки
                }
                expect(err).to.not.exist;
                expect(client.contextComplete).to.be.true;
                done();
              });
            }
          );
        });
      });
    });
  });
});

FROM gcr.io/web-gke/node-base

COPY . /src
RUN cd /src && npm install
EXPOSE 9090
CMD ["node", "/src/bin/www"]

FROM       python:3.5.1-alpine
MAINTAINER Alex Banna alexb@tune.com
ENV        REFRESHED_AT 2015-12-08

# Define app env vars
ENV APP_NAME customs
ENV HOME /opt/$APP_NAME

# add source code
ADD ./ $HOME

# change to root home
WORKDIR $HOME

# install python requirementse
RUN set -ex && \
    pip install --upgrade pip && \
    pip install -r requirements.txt

ENTRYPOINT ["./bin/customs"]
CMD ['--help']

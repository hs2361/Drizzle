FROM python:3.10.1

EXPOSE 1234
EXPOSE 4321

WORKDIR /Drizzle/src

RUN rm -rf ./*
COPY ./client .
COPY ./utils ./utils
COPY ./share ../share

RUN pip install pipenv
RUN pipenv install --system --deploy --ignore-pipfile
# RUN mkdir ../share
RUN mkdir ../share/sub

RUN fallocate -l 5M ../share/test2.file
RUN fallocate -l 5K ../share/sub/test3.file
RUN fallocate -l 1G ../share/sub/test1.file
RUN fallocate -l 100M ../share/sub/test4.file
RUN fallocate -l 10M ../share/sub/test5.file
RUN fallocate -l 10M ../share/sub/test6.file
RUN fallocate -l 10M ../share/sub/test7.file
RUN fallocate -l 10M ../share/sub/test8.file
RUN fallocate -l 10M ../share/sub/test9.file
RUN fallocate -l 10M ../share/sub/test10.file
RUN fallocate -l 10M ../share/sub/test11.file
RUN fallocate -l 10M ../share/sub/test12.file
RUN fallocate -l 10M ../share/sub/test13.file


ENTRYPOINT [ "python", "client.py" ]

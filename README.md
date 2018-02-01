# List all your AWS resources that are publicly exposed

This tool allow for auditing and list your services exposed to public access

It currently list your EC2 and ELB resources that have open ports exposed to the internet.
It generates a csv file.

## Requirements

Below are requirements for a standalone installation. If you wish, a Dockerfile is available to run in a container. Those instructions are available below.

### System packages

The only requirement for the script to work is `Python 2.7`

### Python packages

The python packages dependencies are listed in `requirements.txt`

The only dependency is `boto3`

Dependencies can be installed via :

```
pip install -r requirements.txt
```

## Usage

## Docker container

You will need to have [Docker](https://www.docker.com) installed.

After that, you can build the image from the Dockerfile `docker build -t dockerfile/check-aws-publicly-exposed .`

You can then run the docker container :
```
docker run -it --rm \
--env AWS_ACCESS_KEY_ID={Your AWS access key} \
--env AWS_SECRET_ACCESS_KEY={Your AWS secret key} \
--env AWS_DEFAULT_REGION={Default region} \
dockerfile/check-aws-publicly-exposed check-aws-publicly-exposed.py
```

---

You can specify the output of your via the option `-o [PATH]`
You can specify an aws profile via the option `--profile [PROFILE]`.
If you specify a profile, you do not need to have the key set in your environment.

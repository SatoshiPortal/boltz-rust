```bash

rm -rf /tmp/boltz-rust/
rm -rf /tmp/boltz-rust-public
mkdir /tmp/boltz-rust-public

cd /tmp
git clone https://github.com/jan3dev/boltz-rust/
cd /tmp/boltz-rust/
git checkout  <branch>
rsync -rlp --exclude '.git'  --exclude 'boltz-rust' --exclude 'boltz-rust*' --exclude 'public_repo_instructions.md' --exclude 'target'  * /tmp/boltz-rust-public/
scp -r -i ~/.ssh/john-jan3.pem /tmp/boltz-rust-public/*  ec2-user@ec2-35-87-82-133.us-west-2.compute.amazonaws.com:/home/ec2-user/public_repos/boltz-rust/

ssh -i ~/.ssh/john-jan3.pem ec2-user@ec2-35-87-82-133.us-west-2.compute.amazonaws.com

```

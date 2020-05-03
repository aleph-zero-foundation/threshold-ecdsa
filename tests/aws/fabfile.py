'''Routines called by fab. Assumes that all are called from */experiments/aws.'''

from fabric import task


@task
def test_conn(conn):
    ''' Tests if connection is ready '''

    conn.open()

#======================================================================================
#                                    installation
#======================================================================================

@task
def setup(conn):
    ''' Install dependencies in a nonblocking way.'''

    conn.put('setup.sh', '.')
    conn.sudo('apt update', hide='both')
    conn.sudo('apt install dtach', hide='both')
    conn.run('PATH="$PATH:/snap/bin" && dtach -n `mktemp -u /tmp/dtach.XXXX` bash setup.sh', hide='both')

@task
def setup_completed(conn):
    ''' Check if installation completed.'''

    result = conn.run('tail -1 setup.log')
    return result.stdout.strip()

@task
def clone_repo(conn):
    '''Clones main repo.'''

    repo_path = '/home/ubuntu/go/src/gitlab.com/alephledger/threshold-ecdsa'
    # delete current repo
    conn.run(f'rm -rf {repo_path}')
    # clone using deployment token
    user_token = 'gitlab+deploy-token-70309:G2jUsynd3TQqsvVfn4T7'
    conn.run(f'git clone http://{user_token}@gitlab.com/alephledger/threshold-ecdsa.git {repo_path}')

@task
def build_tecdsa(conn):
    conn.run(f'PATH="$PATH:/snap/bin" && go build /home/ubuntu/go/src/gitlab.com/alephledger/threshold-ecdsa/cmd/tecdsa')

@task
def inst_deps(conn):
    conn.put('deps.sh', '.')
    conn.run('PATH="$PATH:/snap/bin" && dtach -n `mktemp -u /tmp/dtach.XXXX` bash deps.sh', hide='both')

#======================================================================================
#                                   syncing local version
#======================================================================================

@task
def send_keys_addrs(conn):
    ''' Sends keys and addresses, and fixes ip address. '''
    repo_path = '/home/ubuntu/go/src/gitlab.com/alephledger/threshold-ecdsa'
    conn.put('data/keys_addrs', repo_path+'/ka')
    with conn.cd(repo_path):
        conn.run(f'sed s/{conn.host}/$(hostname --ip-address)/g < ka > keys_addrs')

@task
def send_data(conn, pid):
    ''' Sends keys, addresses. '''
    repo_path = '/home/ubuntu/go/src/gitlab.com/alephledger/threshold-ecdsa'
    conn.put(f'data/{pid}.pk', repo_path)
    send_keys_addrs(conn)

@task
def send_repo(conn):
    project_path= '/home/ubuntu/go/src/gitlab.com/alephledger'
    conn.put('core-repo.zip', project_path)
    conn.run(f'rm -rf {project_path}/core-go')
    conn.run(f'unzip -q {project_path}/core-repo.zip -d {project_path}')

    repo_path = project_path + '/threshold-ecdsa'
    conn.run(f'rm -rf {repo_path}')
    conn.run(f'mkdir {repo_path}')
    conn.put('tecdsa-repo.zip', repo_path)
    conn.run(f'rm -rf {repo_path}/pkg {repo_path}/cmd')
    conn.run(f'unzip -q {repo_path}/tecdsa-repo.zip -d {repo_path}')


#======================================================================================
#                                   run experiments
#======================================================================================

@task
def run_protocol(conn, pid, startTime):
    ''' Runs the protocol.'''

    repo_path = '/home/ubuntu/go/src/gitlab.com/alephledger/threshold-ecdsa'
    with conn.cd(repo_path):
        conn.run('rm -f out')
        conn.run(f'PATH="$PATH:/snap/bin" && go build {repo_path}/cmd/tecdsa')
        cmd = f'./tecdsa --pk {pid}.pk\
                    --keys_addrs keys_addrs\
                    --roundDuration 100ms\
                    --startTime "{startTime}"'
        x = f'dtach -n `mktemp -u /tmp/dtach.XXXX` {cmd}'
        conn.run(f'echo {x} > x')
        conn.run(f'dtach -n `mktemp -u /tmp/dtach.XXXX` {cmd}')

@task
def run_protocol_profiler(conn, pid, delay='0'):
    ''' Runs the protocol.'''

    repo_path = '/home/ubuntu/go/src/gitlab.com/alephledger/threshold-ecdsa'
    with conn.cd(repo_path):
        conn.run('rm -f out')
        cmd = f'go run cmd/tecdsa/main.go \
                    --pk {pid}.pk\
                    --keys_addrs keys_addrs\
                    --roundDuration 100ms\
                    --startTime {startTime}'
        if int(pid) % 16 == 0 :
            cmd += ' --cpuprof cpuprof --memprof memprof --mf 5 --bf 0'
        conn.run(f'dtach -n `mktemp -u /tmp/dtach.XXXX` {cmd}')

@task
def stop_world(conn):
    ''' Kills the committee member.'''

    conn.run('pkill --signal QUIT -f tecdsa')

#======================================================================================
#                                        get data
#======================================================================================

@task
def get_profile(conn, pid):
    ''' Retrieves aleph.log from the server.'''

    repo_path = '/home/ubuntu/go/src/gitlab.com/alephledger/threshold-ecdsa'
    with conn.cd(repo_path):
        conn.run(f'cp cpuprof {pid}.cpuprof')
        conn.run(f'cp memprof {pid}.memprof')
        conn.run(f'zip -q prof.zip {pid}.cpuprof {pid}.memprof')
    conn.get(f'{repo_path}/prof.zip', f'../results/{pid}.prof.zip')

@task
def get_log(conn, pid):
    ''' Retrieves aleph.log from the server.'''

    repo_path = '/home/ubuntu/go/src/gitlab.com/alephledger/threshold-ecdsa'
    with conn.cd(repo_path):
        conn.run(f'cp aleph.log {pid}.log')
        conn.run(f'zip -q {pid}.log.zip {pid}.log')
    conn.get(f'{repo_path}/{pid}.log.zip', f'../results/{pid}.log.zip')

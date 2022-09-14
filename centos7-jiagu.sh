#!/bin/bash

#口令相关配置
minlen=8
PASS_MAX_DAYS=90
PASS_MIN_DAYS=10
PASS_WARN_AGE=7
remember=3
deny=5

#登录超时时间
TMOUT=900

#history命令打印的历史命令条数
history_num=0
#配置审计员与安全员
audit_user=audit_user
audit_group=audit_group
sec_user=sec_user
sec_group=sec_group

echo \*\*\*\* 开始自动配置安全基线

# 设置口令长度最小值和密码复杂度策略
echo
echo \*\*\*\* 设置口令长度最小值和密码复杂度策略
# 大写字母、小写字母、数字、特殊字符 4选3，可自行配置
# 配置system-auth
cp /etc/pam.d/system-auth /etc/pam.d/'system-auth-'`date +%Y%m%d`.bak
egrep -q "^\s*password\s*(requisite|required)\s*pam_cracklib.so.*$" /etc/pam.d/system-auth  && sed -ri "s/^\s*password\s*(requisite|required)\s*pam_cracklib.so.*$/\password    requisite     pam_cracklib.so try_first_pass retry=3 minlen=$minlen dcredit=-1 ocredit=-1 lcredit=-1/" /etc/pam.d/system-auth || echo "password    requisite     pam_cracklib.so try_first_pass retry=3 minlen=$minlen dcredit=-1 ocredit=-1 lcredit=-1" >> /etc/pam.d/system-auth
# 配置password-auth
cp /etc/pam.d/password-auth /etc/pam.d/'password-auth-'`date +%Y%m%d`.bak
egrep -q "^\s*password\s*(requisite|required)\s*pam_cracklib.so.*$" /etc/pam.d/password-auth && sed -ri "s/^\s*password\s*(requisite|required)\s*pam_cracklib.so.*$/\password    requisite     pam_cracklib.so try_first_pass retry=3 minlen=$minlen dcredit=-1 ocredit=-1 lcredit=-1/" /etc/pam.d/password-auth || echo "password    requisite     pam_cracklib.so try_first_pass retry=3 minlen=$minlen dcredit=-1 ocredit=-1 lcredit=-1" >> /etc/pam.d/password-auth
# 配置login.defs
cp /etc/login.defs /etc/'login.defs-'`date +%Y%m%d`.bak
egrep -q "^\s*PASS_MIN_LEN\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MIN_LEN\s+\S*(\s*#.*)?\s*$/\PASS_MIN_LEN    $minlen/" /etc/login.defs || echo "PASS_MIN_LEN    $minlen" >> /etc/login.defs

# 设置口令生存周期（可选,缺省不配置）

echo
echo \*\*\*\* 设置口令生存周期
egrep -q "^\s*PASS_MAX_DAYS\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MAX_DAYS\s+\S*(\s*#.*)?\s*$/\PASS_MAX_DAYS   $PASS_MAX_DAYS/" /etc/login.defs || echo "PASS_MAX_DAYS   $PASS_MAX_DAYS" >> /etc/login.defs
egrep -q "^\s*PASS_MIN_DAYS\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_MIN_DAYS\s+\S*(\s*#.*)?\s*$/\PASS_MIN_DAYS   $PASS_MIN_DAYS/" /etc/login.defs || echo "PASS_MIN_DAYS   $PASS_MIN_DAYS" >> /etc/login.defs
egrep -q "^\s*PASS_WARN_AGE\s+\S*(\s*#.*)?\s*$" /etc/login.defs && sed -ri "s/^(\s*)PASS_WARN_AGE\s+\S*(\s*#.*)?\s*$/\PASS_WARN_AGE   $PASS_WARN_AGE/" /etc/login.defs || echo "PASS_WARN_AGE   $PASS_WARN_AGE" >> /etc/login.defs


# 用户认证失败次数限制
echo
echo \*\*\*\* 连续登录失败5次锁定帐号5分钟
cp /etc/pam.d/sshd /etc/pam.d/'sshd-'`date +%Y%m%d`.bak
cp /etc/pam.d/login /etc/pam.d/'login-'`date +%Y%m%d`.bak
sed -ri "/^\s*auth\s+required\s+pam_tally2.so\s+.+(\s*#.*)?\s*$/d" /etc/pam.d/sshd /etc/pam.d/login /etc/pam.d/system-auth /etc/pam.d/password-auth
sed -ri "1a auth       required     pam_tally2.so deny=$deny unlock_time=1800 even_deny_root root_unlock_time=30" /etc/pam.d/sshd /etc/pam.d/login /etc/pam.d/system-auth /etc/pam.d/password-auth
egrep -q "^\s*account\s+required\s+pam_tally2.so\s*(\s*#.*)?\s*$" /etc/pam.d/sshd || sed -ri '/^password\s+.+(\s*#.*)?\s*$/i\account    required     pam_tally2.so' /etc/pam.d/sshd
egrep -q "^\s*account\s+required\s+pam_tally2.so\s*(\s*#.*)?\s*$" /etc/pam.d/login || sed -ri '/^password\s+.+(\s*#.*)?\s*$/i\account    required     pam_tally2.so' /etc/pam.d/login
egrep -q "^\s*account\s+required\s+pam_tally2.so\s*(\s*#.*)?\s*$" /etc/pam.d/system-auth || sed -ri '/^account\s+required\s+pam_permit.so\s*(\s*#.*)?\s*$/a\account     required      pam_tally2.so' /etc/pam.d/system-auth
egrep -q "^\s*account\s+required\s+pam_tally2.so\s*(\s*#.*)?\s*$" /etc/pam.d/password-auth || sed -ri '/^account\s+required\s+pam_permit.so\s*(\s*#.*)?\s*$/a\account     required      pam_tally2.so' /etc/pam.d/password-auth

# 用户的umask安全配置
echo
echo \*\*\*\* 配置umask为022
cp /etc/profile /etc/'profile-'`date +%Y%m%d`.bak
egrep -q "^\s*umask\s+\w+.*$" /etc/profile && sed -ri "s/^\s*umask\s+\w+.*$/umask 022/" /etc/profile || echo "umask 022" >> /etc/profile
cp /etc/csh.login /etc/'csh.login-'`date +%Y%m%d`.bak
egrep -q "^\s*umask\s+\w+.*$" /etc/csh.login && sed -ri "s/^\s*umask\s+\w+.*$/umask 022/" /etc/csh.login || echo "umask 022" >>/etc/csh.login
cp /etc/csh.cshrc /etc/'csh.cshrc-'`date +%Y%m%d`.bak
egrep -q "^\s*umask\s+\w+.*$" /etc/csh.cshrc && sed -ri "s/^\s*umask\s+\w+.*$/umask 022/" /etc/csh.cshrc || echo "umask 022" >> /etc/csh.cshrc
cp /etc/bashrc /etc/'bashrc-'`date +%Y%m%d`.bak
egrep -q "^\s*umask\s+\w+.*$" /etc/bashrc && sed -ri "s/^\s*umask\s+\w+.*$/umask 022/" /etc/bashrc || echo "umask 022" >> /etc/bashrc

# 用户目录缺省访问权限设置
echo
echo \*\*\*\* 设置用户目录默认权限为022
egrep -q "^\s*(umask|UMASK)\s+\w+.*$" /etc/login.defs && sed -ri "s/^\s*(umask|UMASK)\s+\w+.*$/UMASK 022/" /etc/login.defs || echo "UMASK 022" >> /etc/login.defs

# 登录超时设置
echo
echo \*\*\*\* 设置登录超时时间为15分钟
cp /etc/ssh/sshd_config /etc/ssh/'sshd_config-'`date +%Y%m%d`.bak
egrep -q "^\s*(export|)\s*TMOUT\S\w+.*$" /etc/profile && sed -ri "s/^\s*(export|)\s*TMOUT.\S\w+.*$/export TMOUT=$TMOUT/" /etc/profile || echo "export TMOUT=$TMOUT" >> /etc/profile
egrep -q "^\s*.*ClientAliveInterval\s\w+.*$" /etc/ssh/sshd_config && sed -ri "s/^\s*.*ClientAliveInterval\s\w+.*$/ClientAliveInterval $TMOUT/" /etc/ssh/sshd_config || echo "ClientAliveInterval $TMOUT " >> /etc/ssh/sshd_config

# 历史命令设置
echo
echo \*\*\*\* 设置保留历史命令的条数为0，并加上时间戳
egrep -q "^\s*HISTSIZE\s*\W+[0-9].+$" /etc/profile && sed -ri "s/^\s*HISTSIZE\W+[0-9].+$/HISTSIZE=$history_num/" /etc/profile || echo "HISTSIZE=$history_num" >> /etc/profile
egrep -q "^\s*HISTTIMEFORMAT\s*\S+.+$" /etc/profile && sed -ri "s/^\s*HISTTIMEFORMAT\s*\S+.+$/HISTTIMEFORMAT='%F %T | '/" /etc/profile || echo "HISTTIMEFORMAT='%F %T | '" >> /etc/profile
egrep -q "^\s*export\s*HISTTIMEFORMAT.*$" /etc/profile || echo "export HISTTIMEFORMAT" >> /etc/profile

# 开启auditd服务
echo
echo \*\*\*\* 开启auditd服务
systemctl enable auditd
systemctl start auditd

# 设置安全员、审计员帐号
echo
echo \*\*\*\* 设置安全员与审计员帐号
# 新建安全员用户组并添加安全员帐号
egrep -q "^$sec_group:" /etc/group || groupadd $sec_group
egrep -q "^$sec_user:" /etc/passwd || useradd $sec_user -g $sec_group -m -s /bin/bash
# 新建审计员用户组并添加审计员帐号
egrep -q "^$audit_group:" /etc/group || groupadd $audit_group
egrep -q "^$audit_user:" /etc/passwd || useradd $audit_user -g $audit_group -m -s /bin/bash
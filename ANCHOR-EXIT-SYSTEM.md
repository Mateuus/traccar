# 🚨 Sistema de Bloqueio Automático por Saída de Âncora

## 📋 Visão Geral

Este sistema implementa bloqueio automático de dispositivos quando eles saem de geofences marcadas como "âncoras". É uma funcionalidade de segurança crítica que deve ser usada apenas em casos de emergência, roubo ou situações de segurança extrema.

## ⚙️ Como Funciona

### 1. **Identificação de Âncoras**
As âncoras são identificadas através de atributos específicos na geofence:
```json
{
  "isAnchor": true,
  "deviceId": 123
}
```

### 2. **Detecção de Saída**
- O sistema monitora continuamente a posição dos dispositivos
- Quando um dispositivo sai de uma geofence marcada como âncora
- O sistema verifica se `isAnchor=true` e `deviceId` corresponde

### 3. **Bloqueio Automático**
- Comando `engineStop` é enviado automaticamente
- Evento `anchorExitBlock` é registrado para auditoria
- Logs detalhados são gerados no console

### 4. **Destruição Automática da Geofence**
- **Configuração**: `event.anchorExit.destroyGeofence=true` (padrão)
- **Funcionalidade**: Remove a geofence após bloqueio para evitar falsos positivos
- **Vantagens**: 
  - Evita bloqueios repetidos se dispositivo voltar à área
  - Previne falsos positivos em movimento oscilatório
  - Mantém sistema limpo após uso da âncora

## 🔧 Configuração

### 1. **Habilitar o Sistema**
Adicione no arquivo `traccar.xml`:
```xml
<entry key="event.anchorExit.enabled">true</entry>
<entry key="event.anchorExit.destroyGeofence">true</entry>
```

### 2. **Criar Âncora via API**
```bash
POST /api/geofences
{
  "name": "Ancora Veiculo 123",
  "area": "CIRCLE (-23.5505 -46.6333, 150)",
  "attributes": {
    "isAnchor": true,
    "deviceId": 123,
    "color": "#ff6b35"
  }
}
```

### 3. **Criar Permissões**
```bash
POST /api/permissions
{
  "deviceId": 123,
  "geofenceId": 456
}
```

## 📊 Eventos Gerados

### Evento: `anchorExitBlock`
```json
{
  "type": "anchorExitBlock",
  "deviceId": 123,
  "geofenceId": 456,
  "eventTime": "2025-01-27T10:30:00Z",
  "geofenceName": "Ancora Veiculo 123"
}
```

## 🔍 Logs do Sistema

### Console Output
```
🔒 Dispositivo 123 bloqueado automaticamente por sair da âncora: Ancora Veiculo 123
🗑️ Geofence âncora destruída automaticamente: Ancora Veiculo 123 (ID: 456) para evitar falsos positivos
```

### Em caso de erro:
```
❌ Erro ao bloquear dispositivo 123 por sair da âncora: [detalhes do erro]
❌ Erro ao destruir geofence âncora 456: [detalhes do erro]
```

## ⚙️ Configurações Avançadas

### **Destruição Automática da Geofence**

#### **Habilitada (Padrão)**
```xml
<entry key="event.anchorExit.destroyGeofence">true</entry>
```
- ✅ **Vantagens**: Evita falsos positivos, mantém sistema limpo
- ✅ **Uso**: Casos de roubo, emergências, testes únicos
- ⚠️ **Consideração**: Âncora é perdida após uso

#### **Desabilitada**
```xml
<entry key="event.anchorExit.destroyGeofence">false</entry>
```
- ✅ **Vantagens**: Âncora permanece ativa para uso contínuo
- ✅ **Uso**: Monitoramento contínuo, controle de acesso
- ⚠️ **Consideração**: Pode gerar bloqueios repetidos

### **Cenários de Uso**

#### **Cenário 1: Roubo/Emergência (Recomendado)**
```xml
<entry key="event.anchorExit.enabled">true</entry>
<entry key="event.anchorExit.destroyGeofence">true</entry>
```
- Bloqueia dispositivo e destrói âncora
- Evita falsos positivos
- Ideal para situações críticas

#### **Cenário 2: Monitoramento Contínuo**
```xml
<entry key="event.anchorExit.enabled">true</entry>
<entry key="event.anchorExit.destroyGeofence">false</entry>
```
- Bloqueia dispositivo mas mantém âncora
- Permite monitoramento contínuo
- Ideal para controle de acesso

#### **Cenário 3: Sistema Desabilitado**
```xml
<entry key="event.anchorExit.enabled">false</entry>
```
- Sistema completamente desabilitado
- Ideal para desenvolvimento/testes

## ⚠️ Considerações de Segurança

### **USO APENAS EM:**
- ✅ Roubo confirmado
- ✅ Emergência médica
- ✅ Situação de segurança extrema
- ✅ Testes controlados

### **NÃO USAR PARA:**
- ❌ Monitoramento rotineiro
- ❌ Controle de acesso normal
- ❌ Gestão de frota padrão

## 🛠️ Implementação Técnica

### Arquivos Criados/Modificados:

1. **`AnchorExitEventHandler.java`**
   - Handler principal que detecta saída de âncoras
   - Envia comando `engineStop` automaticamente
   - Registra eventos para auditoria

2. **`Keys.java`**
   - Adicionada chave: `EVENT_ANCHOR_EXIT_ENABLED`
   - Configuração: `event.anchorExit.enabled`

3. **`Event.java`**
   - Adicionado tipo: `TYPE_ANCHOR_EXIT_BLOCK`

4. **`ProcessingHandler.java`**
   - Registrado `AnchorExitEventHandler` na pipeline

## 🧪 Testando o Sistema

### 1. **Teste Manual**
```bash
# 1. Criar âncora
curl -X POST http://localhost:8082/api/geofences \
  -H "Content-Type: application/json" \
  -d '{"name":"Teste Ancora","area":"CIRCLE (-23.5505 -46.6333, 150)","attributes":{"isAnchor":true,"deviceId":123}}'

# 2. Criar permissão
curl -X POST http://localhost:8082/api/permissions \
  -H "Content-Type: application/json" \
  -d '{"deviceId":123,"geofenceId":456}'

# 3. Simular movimento do dispositivo para fora da âncora
# O sistema deve bloquear automaticamente
```

### 2. **Verificar Eventos**
```bash
curl http://localhost:8082/api/events?type=anchorExitBlock
```

## 📈 Monitoramento

### Métricas Importantes:
- Número de bloqueios automáticos por dia
- Tempo de resposta do sistema
- Taxa de sucesso dos comandos
- Eventos de erro

### Alertas Recomendados:
- Falha no envio de comando `engineStop`
- Múltiplos bloqueios do mesmo dispositivo
- Dispositivos offline durante bloqueio

## 🔄 Desbloqueio

Para desbloquear um dispositivo bloqueado automaticamente:

```bash
POST /api/commands/send
{
  "type": "engineResume",
  "deviceId": 123,
  "attributes": {
    "noQueue": true
  }
}
```

## 📝 Logs de Auditoria

Todos os bloqueios automáticos são registrados com:
- Timestamp exato
- ID do dispositivo
- ID da geofence âncora
- Nome da âncora
- Status do comando enviado

## 🚀 Próximos Passos

1. **Testes em ambiente controlado**
2. **Configuração de alertas**
3. **Treinamento da equipe**
4. **Documentação de procedimentos**
5. **Monitoramento contínuo**

---

**⚠️ IMPORTANTE:** Este é um sistema de segurança crítica. Use com responsabilidade e apenas em situações que realmente justifiquem o bloqueio automático de veículos.

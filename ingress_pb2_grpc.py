# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
import grpc

import envelope_pb2 as envelope__pb2
import ingress_pb2 as ingress__pb2


class IngressStub(object):
  # missing associated documentation comment in .proto file
  pass

  def __init__(self, channel):
    """Constructor.

    Args:
      channel: A grpc.Channel.
    """
    self.Sender = channel.stream_unary(
        '/loggregator.v2.Ingress/Sender',
        request_serializer=envelope__pb2.Envelope.SerializeToString,
        response_deserializer=ingress__pb2.IngressResponse.FromString,
        )
    self.BatchSender = channel.stream_unary(
        '/loggregator.v2.Ingress/BatchSender',
        request_serializer=ingress__pb2.EnvelopeBatch.SerializeToString,
        response_deserializer=ingress__pb2.BatchSenderResponse.FromString,
        )


class IngressServicer(object):
  # missing associated documentation comment in .proto file
  pass

  def Sender(self, request_iterator, context):
    # missing associated documentation comment in .proto file
    pass
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def BatchSender(self, request_iterator, context):
    # missing associated documentation comment in .proto file
    pass
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')


def add_IngressServicer_to_server(servicer, server):
  rpc_method_handlers = {
      'Sender': grpc.stream_unary_rpc_method_handler(
          servicer.Sender,
          request_deserializer=envelope__pb2.Envelope.FromString,
          response_serializer=ingress__pb2.IngressResponse.SerializeToString,
      ),
      'BatchSender': grpc.stream_unary_rpc_method_handler(
          servicer.BatchSender,
          request_deserializer=ingress__pb2.EnvelopeBatch.FromString,
          response_serializer=ingress__pb2.BatchSenderResponse.SerializeToString,
      ),
  }
  generic_handler = grpc.method_handlers_generic_handler(
      'loggregator.v2.Ingress', rpc_method_handlers)
  server.add_generic_rpc_handlers((generic_handler,))

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from django.db.models import Q

from .models import Device
from .serializers import DeviceSerializer, DeviceDetailSerializer


class DeviceListView(APIView):
    """
    GET /api/inventory/devices/
    List all inventory devices. Supports:
      - ?search=<query> (searches ip, hostname, vendor, operating_system)
      - ?status=<status> (filters by status: up, down, unknown)
    """

    def get(self, request):
        queryset = Device.objects.all().prefetch_related("ports").order_by("ip")

        search_query = request.query_params.get("search", None)
        if search_query:
            queryset = queryset.filter(
                Q(ip__icontains=search_query)
                | Q(hostname__icontains=search_query)
                | Q(vendor__icontains=search_query)
                | Q(operating_system__icontains=search_query)
            )

        status_param = request.query_params.get("status", None)
        if status_param:
            queryset = queryset.filter(status__iexact=status_param)

        serializer = DeviceSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class DeviceDetailView(APIView):
    """
    GET /api/inventory/devices/<pk>/
    Retrieve detail of a single device including open ports and recent findings.

    DELETE /api/inventory/devices/<pk>/
    Delete a device from inventory.
    """

    def get(self, request, pk):
        device = get_object_or_404(
            Device.objects.prefetch_related("ports"),
            pk=pk
        )
        serializer = DeviceDetailSerializer(device)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, pk):
        device = get_object_or_404(Device, pk=pk)
        device.delete()
        return Response(
            {"message": f"Device #{pk} deleted successfully."},
            status=status.HTTP_204_NO_CONTENT
        )

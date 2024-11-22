from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib import admin


from advent_app.models import User, Task

class TaskAdmin(admin.ModelAdmin):
    pass

class UserAdmin(BaseUserAdmin):
    fieldsets = BaseUserAdmin.fieldsets + (
        (None, {'fields': ('region', 'grade', 'parent_phone', 'country', 'phone')}),
    )

admin.site.register(User, UserAdmin)
admin.site.register(Task, TaskAdmin)